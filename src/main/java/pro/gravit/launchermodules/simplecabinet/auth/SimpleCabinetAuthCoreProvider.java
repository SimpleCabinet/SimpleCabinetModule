package pro.gravit.launchermodules.simplecabinet.auth;

import com.google.gson.JsonElement;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.ClientPermissions;
import pro.gravit.launcher.Launcher;
import pro.gravit.launcher.events.request.GetAvailabilityAuthRequestEvent;
import pro.gravit.launcher.profiles.Texture;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launcher.request.auth.details.AuthPasswordDetails;
import pro.gravit.launcher.request.auth.details.AuthTotpDetails;
import pro.gravit.launcher.request.auth.password.Auth2FAPassword;
import pro.gravit.launcher.request.auth.password.AuthPlainPassword;
import pro.gravit.launcher.request.auth.password.AuthTOTPPassword;
import pro.gravit.launchermodules.simplecabinet.SimpleCabinetRequester;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthException;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.launchserver.auth.core.UserSession;
import pro.gravit.launchserver.auth.core.interfaces.user.UserSupportTextures;
import pro.gravit.launchserver.helper.HttpHelper;
import pro.gravit.launchserver.manangers.AuthManager;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.response.auth.AuthResponse;
import pro.gravit.utils.helper.IOHelper;
import pro.gravit.utils.helper.SecurityHelper;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

public class SimpleCabinetAuthCoreProvider extends AuthCoreProvider {
    public String baseUrl;
    public String adminJwtToken;
    public String jwtPublicKeyPath;
    private transient JwtParser parser;
    private transient final Logger logger = LogManager.getLogger();
    private transient ECPublicKey jwtPublicKey;
    private transient SimpleCabinetRequester request;

    public SimpleCabinetUser getUserById(long id) {
        try {
            return request.send(request.get(String.format("/users/id/%d", id), null), SimpleCabinetUser.class).getOrThrow();
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
            return request.send(request.get(String.format("/users/name/%s", urlEncode(username)), null), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public User getUserByUUID(UUID uuid) {
        try {
            return request.send(request.get(String.format("/users/uuid/%s", uuid.toString()), null), SimpleCabinetUser.class).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public UserSession getUserSessionByOAuthAccessToken(String accessToken) throws OAuthAccessTokenExpired {
        try {
            CabinetUserDetails details = getDetailsFromToken(accessToken);
            return details.toSession();
        } catch (Exception e) {
            if(e instanceof ExpiredJwtException) {
                throw new OAuthAccessTokenExpired();
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
    public boolean joinServer(Client client, String username, String accessToken, String serverID) throws IOException {
        SimpleCabinetUser user = (SimpleCabinetUser) client.getUser();
        if(!user.getUsername().equals(username)) {
            return false;
        }
        var result = request.send(request.post("/admin/server/joinserver", new CabinetJoinServerRequest(client.sessionObject.getID(), serverID), adminJwtToken), CabinetJoinServerResponse.class).getOrThrow();
        return result.success;
    }

    @Override
    protected boolean updateServerID(User user, String serverID) throws IOException {
        throw new UnsupportedOperationException("Method updateServerID not supported");
    }

    @Override
    public void close() throws IOException {

    }

    public record CabinetAuthRequest(String username, String password, String totpPassword) {
    }

    public record CabinetMinecraftAccessRequest(String userAccessToken) {
    }

    public static final class CabinetMinecraftAccessResponse {
        public String minecraftAccessToken;

        public CabinetMinecraftAccessResponse(String minecraftAccessToken) {
            this.minecraftAccessToken = minecraftAccessToken;
        }
    }

    public record CabinetCheckServerRequest(String username, String serverID) {
    }

    public record CabinetJoinServerRequest(String sessionId,
                                           String serverID) {
    }

    public static final class CabinetJoinServerResponse {
        public boolean success;

        public CabinetJoinServerResponse(boolean success) {
            this.success = success;
        }
    }

    public class CabinetUserDetails {
        public long id;
        public String username;
        public List<String> roles;
        public String client;
        public long sessionId;
        public long expireIn;

        public CabinetUserDetails(long id, String username, List<String> roles, String client, long sessionId, long expireIn) {
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
            session.user = getUserById(id);
            return session;
        }
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
        return new CabinetUserDetails(userId, claims.getSubject(), roles, client, sessionId, expire == null ? 0 : expire.toInstant().toEpochMilli());
    }

    public static class SimpleCabinetUser implements User, UserSupportTextures {
        public long id;
        public String username;
        public UUID uuid;
        transient String accessToken;
        public long permissions;
        public long flags;

        @Override
        public Texture getSkinTexture() {
            return skin;
        }

        @Override
        public Texture getCloakTexture() {
            return cloak;
        }

        public enum Gender {
            MALE, FEMALE
        }
        public Gender gender;
        public String status;
        public Texture skin;
        public Texture cloak;

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public UUID getUUID() {
            return uuid;
        }

        @Override
        public String getServerId() {
            return null;
        }

        @Override
        public String getAccessToken() {
            return accessToken == null ? "ignored" : accessToken;
        }

        @Override
        public ClientPermissions getPermissions() {
            return new ClientPermissions(permissions, flags);
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
                    ", permissions=" + permissions +
                    ", flags=" + flags +
                    ", gender=" + gender +
                    ", status='" + status + '\'' +
                    ", skin=" + skin +
                    ", cloak=" + cloak +
                    '}';
        }
    }

    public static class SimpleCabinetUserSession implements UserSession {
        public String id;
        public SimpleCabinetUser user;
        public long expireIn;

        @Override
        public String getID() {
            return id;
        }

        @Override
        public User getUser() {
            return user;
        }

        @Override
        public long getExpireIn() {
            return expireIn;
        }
    }
}