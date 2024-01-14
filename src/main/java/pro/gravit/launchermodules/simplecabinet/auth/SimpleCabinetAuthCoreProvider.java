package pro.gravit.launchermodules.simplecabinet.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.base.ClientPermissions;
import pro.gravit.launcher.base.events.request.GetAvailabilityAuthRequestEvent;
import pro.gravit.launcher.base.profiles.Texture;
import pro.gravit.launcher.base.request.auth.AuthRequest;
import pro.gravit.launcher.base.request.auth.details.AuthPasswordDetails;
import pro.gravit.launcher.base.request.auth.details.AuthTotpDetails;
import pro.gravit.launcher.base.request.auth.password.Auth2FAPassword;
import pro.gravit.launcher.base.request.auth.password.AuthPlainPassword;
import pro.gravit.launcher.base.request.auth.password.AuthTOTPPassword;
import pro.gravit.launcher.base.request.secure.HardwareReportRequest;
import pro.gravit.launchermodules.simplecabinet.SimpleCabinetRequester;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthException;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.auth.core.interfaces.UserHardware;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportAssetUpload;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportExtendedCheckServer;
import pro.gravit.launchserver.auth.core.interfaces.provider.AuthSupportHardware;
import pro.gravit.launchserver.auth.core.interfaces.session.UserSessionSupportHardware;
import pro.gravit.launchserver.auth.core.interfaces.user.UserSupportTextures;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;
import pro.gravit.launchserver.socket.response.auth.CheckServerResponse;
import pro.gravit.utils.helper.IOHelper;
import pro.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;

public class SimpleCabinetAuthCoreProvider extends AuthCoreProvider implements AuthSupportHardware, AuthSupportAssetUpload, AuthSupportExtendedCheckServer {
    public String baseUrl;
    public String adminJwtToken;
    public String jwtPublicKeyPath;
    private transient JwtParser parser;
    private transient final Logger logger = LogManager.getLogger();
    private transient ECPublicKey jwtPublicKey;
    private transient SimpleCabinetRequester request;

    public SimpleCabinetUser getUserById(long id) {
        try {
            return request.send(request.get(String.format("/users/id/%d?assets=true", id), null), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public List<GetAvailabilityAuthRequestEvent.AuthAvailabilityDetails> getDetails(Client client) {
        return List.of(new AuthPasswordDetails(), new AuthTotpDetails("TOTP", 6));
    }

    private String urlEncode(String string) {
        return URLEncoder.encode(string, StandardCharsets.UTF_8);
    }

    @Override
    public User getUserByUsername(String username) {
        try {
            return request.send(request.get(String.format("/users/name/%s?assets=true", urlEncode(username)), null), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public User getUserByUUID(UUID uuid) {
        try {
            return request.send(request.get(String.format("/users/uuid/%s?assets=true", uuid.toString()), null), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public UserSession getUserSessionByOAuthAccessToken(String accessToken) throws OAuthAccessTokenExpired {
        try {
            CabinetUserDetails details = getDetailsFromToken(accessToken);
            var session = details.toSession();
            if(session.user == null) { // User deleted
                throw new OAuthAccessTokenExpired();
            }
            return session;
        } catch (Exception e) {
            if(e instanceof ExpiredJwtException) {
                throw new OAuthAccessTokenExpired();
            }
            if(e instanceof OAuthAccessTokenExpired) {
                throw (OAuthAccessTokenExpired) e;
            }
            else {
                logger.error("JWT error", e);
            }
            return null;
        }
    }

    @Override
    public AuthManager.AuthReport refreshAccessToken(String refreshToken, AuthResponse.AuthContext context) {
        try {
            var result = request.send(request.post("/auth/refresh", new RefreshTokenRequest(refreshToken), null), CabinetTokenResponse.class);
            if(result.isSuccessful()) {
                var data = result.result();
                return AuthManager.AuthReport.ofOAuth(data.accessToken, data.refreshToken, data.expire, null);
            }
        } catch (IOException e) {
            logger.error("refreshAccessToken", e);
        }
        return null;
    }

    @Override
    public AuthManager.AuthReport authorize(String login, AuthResponse.AuthContext context, AuthRequest.AuthPasswordInterface password, boolean minecraftAccess) throws IOException {
        if(login == null) {
            throw AuthException.userNotFound();
        }
        if(password == null) {
            throw AuthException.wrongPassword();
        }
        CabinetAuthRequest request;
        if(password instanceof Auth2FAPassword) {
            AuthPlainPassword password1 = (AuthPlainPassword) ((Auth2FAPassword) password).firstPassword;
            AuthTOTPPassword password2 = (AuthTOTPPassword) ((Auth2FAPassword) password).secondPassword;
            request = new CabinetAuthRequest(login, password1.password, password2.totp);
        } else if(password instanceof AuthPlainPassword) {
            request = new CabinetAuthRequest(login, ((AuthPlainPassword) password).password, null);
        } else {
            throw AuthException.wrongPassword();
        }
        var result = this.request.send(this.request.post("/auth/authorize", request, null), CabinetTokenResponse.class);
        if(result.isSuccessful()) {
            var data = result.result();
            var details = getDetailsFromToken(data.accessToken);
            var session = details.toSession();
            if(minecraftAccess) {
                return AuthManager.AuthReport.ofOAuthWithMinecraft(data.accessToken, data.accessToken, data.refreshToken, data.expire, session);
            }
            return AuthManager.AuthReport.ofOAuth(data.accessToken, data.refreshToken, data.expire, session);
        } else if(result.error().code == 1 + 7) {
            throw AuthException.need2FA();
        } else {
            throw new AuthException(result.error().error);
        }
    }

    @Override
    public void init(LaunchServer server) {
        try {
            request = new SimpleCabinetRequester(baseUrl);
            jwtPublicKey = SecurityHelper.toPublicECDSAKey(IOHelper.read(Paths.get(jwtPublicKeyPath)));
        } catch (InvalidKeySpecException | IOException e) {
            throw new RuntimeException(e);
        }
        parser = Jwts.parserBuilder()
                .requireIssuer("SimpleCabinet")
                .setSigningKey(jwtPublicKey)
                .build();
    }

    @Override
    public User checkServer(Client client, String username, String serverID) throws IOException {
        return request.send(request.post("/admin/server/checkserver", new CabinetCheckServerRequest(username, serverID), adminJwtToken), SimpleCabinetUser.class).getOrThrow();
    }

    @Override
    public boolean joinServer(Client client, String username, UUID uuid, String accessToken, String serverID) throws IOException {
        SimpleCabinetUser user = (SimpleCabinetUser) client.getUser();
        if(uuid != null) {
            if(!user.getUUID().equals(uuid)) {
                return false;
            }
        } else {
            if(!user.getUsername().equals(username)) {
                return false;
            }
        }
        var result = request.send(request.post("/admin/server/joinserver", new CabinetJoinServerRequest(client.sessionObject.getID(), serverID), adminJwtToken), CabinetJoinServerResponse.class).getOrThrow();
        return result.success;
    }

    @Override
    public void close() {

    }

    @Override
    public UserHardware getHardwareInfoByPublicKey(byte[] publicKey) {
        try {
            return request.send(request.get(String.format("/admin/hardware/publickey/%s", Base64.getUrlEncoder().encodeToString(publicKey)), adminJwtToken), CabinetUserHardware.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getHardwareInfoByPublicKey", e);
            return null;
        }
    }

    @Override
    public UserHardware getHardwareInfoByData(HardwareReportRequest.HardwareInfo info) {
        try {
            return request.send(request.post("/admin/hardware/search", CabinetHardwareSearchRequest.fromHardwareInfo(info), adminJwtToken), CabinetUserHardware.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getHardwareInfoByData", e);
            return null;
        }
    }

    @Override
    public UserHardware getHardwareInfoById(String id) {
        try {
            return request.send(request.get(String.format("/admin/hardware/id/%s", id), adminJwtToken), CabinetUserHardware.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getHardwareInfoById", e);
            return null;
        }
    }

    @Override
    public UserHardware createHardwareInfo(HardwareReportRequest.HardwareInfo info, byte[] publicKey) {
        try {
            return request.send(request.put("/admin/hardware/new", CabinetHardwareCreateRequest.fromHardwareInfo(info, publicKey), adminJwtToken), CabinetUserHardware.class).getOrThrow();
        } catch (IOException e) {
            logger.error("createHardwareInfo", e);
            return null;
        }
    }

    @Override
    public void connectUserAndHardware(UserSession userSession, UserHardware hardware) {
        var session = (SimpleCabinetUserSession) userSession;
        var cabinetHardware = (CabinetUserHardware) hardware;
        try {
            request.send(request.post(String.format("/admin/session/id/%s/sethardware", session.id), new CabinetSetHardwareRequest(cabinetHardware.id), adminJwtToken), Void.class).getOrThrow();
        } catch (IOException e) {
            logger.error("addPublicKeyToHardwareInfo", e);
        }
    }

    @Override
    public void addPublicKeyToHardwareInfo(UserHardware hardware, byte[] publicKey) {
        try {
            request.send(request.post(String.format("/admin/hardware/id/%s/setpublickey", hardware.getId()), new CabinetSetPublicKeyRequest(publicKey), adminJwtToken), Void.class).getOrThrow();
        } catch (IOException e) {
            logger.error("addPublicKeyToHardwareInfo", e);
        }
    }

    @Override
    public Iterable<User> getUsersByHardwareInfo(UserHardware hardware) {
        throw new UnsupportedOperationException("getUsersByHardwareInfo not implemented");
    }

    @Override
    public void banHardware(UserHardware hardware) {
        throw new UnsupportedOperationException("banHardware not implemented");
    }

    @Override
    public void unbanHardware(UserHardware hardware) {
        throw new UnsupportedOperationException("unbanHardware not implemented");
    }

    public SimpleCabinetUser getUserByAccessToken(String accessToken) {
        try {
            return request.send(request.get("/auth/userinfo", accessToken), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserByAccessToken", e);
            return null;
        }
    }

    @Override
    public String getAssetUploadUrl(String name, User user) {
        return baseUrl.concat("/cabinet/upload/".concat(name.toLowerCase(Locale.ROOT)));
    }

    @Override
    public UserSession extendedCheckServer(Client client, String username, String serverID) throws IOException {
        var response = request.send(request.post("/admin/server/extendedcheckserver", new CabinetCheckServerRequest(username, serverID), adminJwtToken), ExtendedCheckServerResponse.class).getOrThrow();
        var result = new SimpleCabinetUserSession();
        result.user = response.user();
        result.id = String.valueOf(response.session().id);
        result.hardwareId = response.session().hardwareId();
        result.accessToken = null;
        return result;
    }

    public record CabinetAuthRequest(String username, String password, String totpPassword) {
    }

    public record CabinetCheckServerRequest(String username, String serverID) {
    }

    public record CabinetJoinServerRequest(String sessionId,
                                           String serverID) {
    }

    public record CabinetHardwareCreateRequest(int bitness,
                                        long totalMemory,
                                        int logicalProcessors,
                                        int physicalProcessors,
                                        long processorMaxFreq,
                                        boolean battery,
                                        String hwDiskId,
                                        String displayId,
                                        String baseboardSerialNumber, String publicKey) {
        public static CabinetHardwareCreateRequest fromHardwareInfo(HardwareReportRequest.HardwareInfo info, byte[] publicKey) {
            return new CabinetHardwareCreateRequest(info.bitness, info.totalMemory, info.logicalProcessors, info.physicalProcessors,
                    info.processorMaxFreq, info.battery, info.hwDiskId, info.displayId == null ? null :  Base64.getEncoder().encodeToString(info.displayId), info.baseboardSerialNumber,
                    Base64.getEncoder().encodeToString(publicKey));
        }
    }

    public record CabinetHardwareSearchRequest(int bitness,
                                        long totalMemory,
                                        int logicalProcessors,
                                        int physicalProcessors,
                                        long processorMaxFreq,
                                        boolean battery,
                                        String hwDiskId,
                                        String displayId,
                                        String baseboardSerialNumber) {
        public static CabinetHardwareSearchRequest fromHardwareInfo(HardwareReportRequest.HardwareInfo info) {
            return new CabinetHardwareSearchRequest(info.bitness, info.totalMemory, info.logicalProcessors, info.physicalProcessors,
                    info.processorMaxFreq, info.battery, info.hwDiskId, info.displayId == null ? null : Base64.getEncoder().encodeToString(info.displayId), info.baseboardSerialNumber);
        }
    }

    public record CabinetSetPublicKeyRequest(String publicKey) {
        public CabinetSetPublicKeyRequest(byte[] publicKey) {
            this(Base64.getEncoder().encodeToString(publicKey));
        }
    }

    public record CabinetSetHardwareRequest(long id) {
    }

    public static final class CabinetJoinServerResponse {
        public boolean success;

        public CabinetJoinServerResponse(boolean success) {
            this.success = success;
        }
    }

    public class CabinetUserDetails {

        public transient String accessToken;
        public long id;
        public String username;
        public List<String> roles;
        public String client;
        public long sessionId;
        public long expireIn;

        public CabinetUserDetails(String accessToken, long id, String username, List<String> roles, String client, long sessionId, long expireIn) {
            this.accessToken = accessToken;
            this.id = id;
            this.username = username;
            this.roles = roles;
            this.client = client;
            this.sessionId = sessionId;
            this.expireIn = expireIn;
        }

        public SimpleCabinetUserSession toSession() {
            SimpleCabinetUserSession session = new SimpleCabinetUserSession();
            session.id = String.valueOf(sessionId);
            session.expireIn = expireIn;
            if(accessToken != null) {
                session.user = getUserByAccessToken(accessToken);
            }
            if(session.user == null) {
                session.user = getUserById(id);
            }
            return session;
        }
    }

    public static class CabinetUserHardware implements UserHardware {
        public long id;
        public int bitness;
        public long totalMemory;
        public int logicalProcessors;
        public int physicalProcessors;
        public long processorMaxFreq;
        public boolean battery;
        public String hwDiskId;
        public String displayId;
        public String baseboardSerialNumber;
        public String publicKey;
        public boolean banned;

        @Override
        public HardwareReportRequest.HardwareInfo getHardwareInfo() {
            var hardware = new HardwareReportRequest.HardwareInfo();
            hardware.baseboardSerialNumber = baseboardSerialNumber;
            hardware.battery = battery;
            hardware.totalMemory = totalMemory;
            hardware.logicalProcessors = logicalProcessors;
            hardware.physicalProcessors = physicalProcessors;
            hardware.bitness = bitness;
            hardware.processorMaxFreq = processorMaxFreq;
            hardware.hwDiskId = hwDiskId;
            hardware.displayId = Base64.getDecoder().decode(displayId);
            return hardware;
        }

        @Override
        public byte[] getPublicKey() {
            return Base64.getDecoder().decode(publicKey);
        }

        @Override
        public String getId() {
            return String.valueOf(id);
        }

        @Override
        public boolean isBanned() {
            return banned;
        }
    }

    public record ExtendedCheckServerResponse(SimpleCabinetUser user, SimpleCabinetSessionResponse session) {
    }

    public static class CabinetTokenResponse {
        public String accessToken;
        public String refreshToken;
        public long expire;
    }

    public record RefreshTokenRequest(String refreshToken) {
    }



    @SuppressWarnings("unchecked")
    public CabinetUserDetails getDetailsFromToken(String token) throws ExpiredJwtException {
        Claims claims = parser
                .parseClaimsJws(token).getBody();
        List<String> roles = claims.get("roles", List.class);
        String client = claims.get("client", String.class);
        long userId = (long)(double) claims.get("id", Double.class);
        long sessionId = (long)(double) claims.get("sessionId", Double.class);
        var expire = claims.getExpiration();
        return new CabinetUserDetails(token, userId, claims.getSubject(), roles, client, sessionId, expire == null ? 0 : expire.toInstant().toEpochMilli());
    }

    public record SimpleCabinetSessionResponse(long id, String client, String createdAt, boolean hardware, Long hardwareId, boolean active) {

    }

    public static class SimpleCabinetUser implements User, UserSupportTextures {
        public long id;
        public String username;
        public UUID uuid;

        @Override
        public Texture getSkinTexture() {
            return assets.get("skin");
        }

        @Override
        public Texture getCloakTexture() {
            return assets.get("cape");
        }

        @Override
        public Map<String, Texture> getUserAssets() {
            Map<String, Texture> result = new HashMap<>();
            for(var e : assets.entrySet()) {
                result.put(e.getKey().toUpperCase(Locale.ROOT), e.getValue());
            }
            return result;
        }

        public enum Gender {
            MALE, FEMALE
        }
        public Gender gender;
        public String status;
        public Map<String, Texture> assets;

        public Map<String, String> permissions;
        public List<UserGroup> groups;

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public UUID getUUID() {
            return uuid;
        }

        @Override
        public ClientPermissions getPermissions() {
            return new ClientPermissions(groups.stream().map(UserGroup::groupName).collect(Collectors.toList()),
                    new ArrayList<>(permissions.keySet()));
        }

        public Gender getGender() {
            return gender;
        }

        public String getStatus() {
            return status;
        }

        @Override
        public String toString() {
            return "SimpleCabinetUser{" +
                    "id=" + id +
                    ", username='" + username + '\'' +
                    ", uuid=" + uuid +
                    ", gender=" + gender +
                    ", status='" + status + '\'' +
                    '}';
        }
    }

    public record UserGroup(long id, String groupName) {

    }

    public class SimpleCabinetUserSession implements UserSession, UserSessionSupportHardware {
        public String id;
        public SimpleCabinetUser user;
        public String accessToken;
        public long expireIn;
        public Long hardwareId;
        private transient CabinetUserHardware hardware;

        @Override
        public String getID() {
            return id;
        }

        @Override
        public User getUser() {
            return user;
        }

        @Override
        public String getMinecraftAccessToken() {
            return "IGNORED";
        }

        @Override
        public long getExpireIn() {
            return expireIn;
        }

        @Override
        public String getHardwareId() {
            return hardwareId == null ? null : String.valueOf(hardwareId);
        }

        @Override
        public UserHardware getHardware() {
            if(hardware == null) {
                if(hardwareId == null) {
                    return null;
                }
                hardware = (CabinetUserHardware) getHardwareInfoById(String.valueOf(hardwareId));
            }
            return hardware;
        }
    }
}
