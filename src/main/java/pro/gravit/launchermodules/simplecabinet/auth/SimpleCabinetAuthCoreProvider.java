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
import pro.gravit.launcher.profiles.Texture;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launcher.request.auth.password.AuthPlainPassword;
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
    private transient final HttpClient httpClient = HttpClient.newBuilder().build();
    private transient JwtParser parser;
    private transient final Logger logger = LogManager.getLogger();
    private transient ECPublicKey jwtPublicKey;

    private static class SimpleCabinetErrorHandler<T> implements HttpHelper.HttpJsonErrorHandler<T, SimpleCabinetError> {
        private final Type type;

        private SimpleCabinetErrorHandler(Type type) {
            this.type = type;
        }

        @Override
        public HttpHelper.HttpOptional<T, SimpleCabinetError> applyJson(JsonElement response, int statusCode) {
            if(statusCode < 200 || statusCode >= 300) {
                return new HttpHelper.HttpOptional<>(null, Launcher.gsonManager.gson.fromJson(response, SimpleCabinetError.class), statusCode);
            }
            return new HttpHelper.HttpOptional<>(Launcher.gsonManager.gson.fromJson(response, type), null, statusCode);
        }
    }

    private<T> SimpleCabinetErrorHandler<T> makeEH(Class<T> clazz) {
        return new SimpleCabinetErrorHandler<>(clazz);
    }

    public SimpleCabinetUser getUserById(long id) {
        try {
            return HttpHelper.send(httpClient, get(String.format("/users/id/%d", id), null), makeEH(SimpleCabinetUser.class)).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    private String urlEncode(String string) {
        return URLEncoder.encode(string, StandardCharsets.UTF_8);
    }

    @Override
    public User getUserByUsername(String username) {
        try {
            return HttpHelper.send(httpClient, get(String.format("/users/name/%s", urlEncode(username)), null), makeEH(SimpleCabinetUser.class)).getOrThrow();
        } catch (IOException e) {
            logger.error("getUserById", e);
            return null;
        }
    }

    @Override
    public User getUserByUUID(UUID uuid) {
        try {
            return HttpHelper.send(httpClient, get(String.format("/users/uuid/%s", uuid.toString()), null), makeEH(SimpleCabinetUser.class)).getOrThrow();
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
            var result = HttpHelper.send(httpClient, post("/auth/refresh", new RefreshTokenRequest(refreshToken), null), makeEH(CabinetTokenResponse.class));
            if(result.isSuccessful()) {
                var data = result.result();
                return AuthManager.AuthReport.ofOAuth(data.accessToken, data.refreshToken, data.expire);
            }
        } catch (IOException e) {
            logger.error("refreshAccessToken", e);
        }
        return null;
    }

    @Override
    public void verifyAuth(AuthResponse.AuthContext context) throws AuthException {

    }

    @Override
    public PasswordVerifyReport verifyPassword(User user, AuthRequest.AuthPasswordInterface password) {
        var request = new CabinetAuthRequest(user.getUsername(), ((AuthPlainPassword)password).password);
        try {
            var result = HttpHelper.send(httpClient, post("/auth/authorize", request, null), makeEH(CabinetTokenResponse.class));
            if(result.isSuccessful()) {
                var data = result.result();
                return new CabinetPasswordVerifyReport(data.accessToken, data.refreshToken, data.expire);
            }
        } catch (IOException e) {
            logger.error("refreshAccessToken", e);
        }
        return PasswordVerifyReport.FAILED;
    }

    @Override
    public AuthManager.AuthReport createOAuthSession(User user, AuthResponse.AuthContext context, PasswordVerifyReport report1, boolean minecraftAccess) throws IOException {
        var report = (CabinetPasswordVerifyReport) report1;
        if(report == null) {
            throw new UnsupportedOperationException();
        }
        var details = getDetailsFromToken(report.accessToken);
        var session = new SimpleCabinetUserSession();
        session.user = (SimpleCabinetUser) user;
        session.id = String.valueOf(details.sessionId);
        session.expireIn = report.expire;
        if(minecraftAccess) {
            return AuthManager.AuthReport.ofOAuthWithMinecraft(report.accessToken, report.accessToken, report.refreshToken, report.expire, session);
        }
        return AuthManager.AuthReport.ofOAuth(report.accessToken, report.refreshToken, report.expire, session);
    }

    @Override
    public void init(LaunchServer server) {
        try {
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
        return HttpHelper.send(httpClient, post("/admin/server/checkserver", new CabinetCheckServerRequest(username, serverID), adminJwtToken), makeEH(SimpleCabinetUser.class)).getOrThrow();
    }

    @Override
    public boolean joinServer(Client client, String username, String accessToken, String serverID) throws IOException {
        SimpleCabinetUser user = (SimpleCabinetUser) client.getUser();
        if(!user.getUsername().equals(username)) {
            return false;
        }
        var result = HttpHelper.send(httpClient, post("/admin/server/joinserver", new CabinetJoinServerRequest(client.sessionObject.getID(), serverID), adminJwtToken), makeEH(CabinetJoinServerResponse.class)).getOrThrow();
        return result.success;
    }

    @Override
    protected boolean updateServerID(User user, String serverID) throws IOException {
        throw new UnsupportedOperationException("Method updateServerID not supported");
    }

    @Override
    public void close() throws IOException {

    }

    public record CabinetAuthRequest(String username, String password) {
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

    public static class CabinetPasswordVerifyReport extends PasswordVerifyReport {
        public String accessToken;
        public String refreshToken;
        public long expire;
        public CabinetPasswordVerifyReport(String accessToken, String refreshToken, long expire) {
            super(true);
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expire = expire;
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


    private<T> HttpRequest get(String url, String token) {
        try {
            var requestBuilder = HttpRequest.newBuilder()
                    .method("GET", HttpRequest.BodyPublishers.noBody())
                    .uri(new URI(baseUrl.concat(url)))
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofMillis(10000));
            if(token != null) {
                requestBuilder.header("Authorization", "Bearer ".concat(token));
            }
            return requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private<T> HttpRequest post(String url, T request, String token) {
        try {
            var requestBuilder = HttpRequest.newBuilder()
                    .method("POST", HttpRequest.BodyPublishers.ofString(Launcher.gsonManager.gson.toJson(request)))
                    .uri(new URI(baseUrl.concat(url)))
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofMillis(10000));
            if(token != null) {
                requestBuilder.header("Authorization", "Bearer ".concat(token));
            }
            return requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static class SimpleCabinetError {
        public String error;

        public SimpleCabinetError(String error) {
            this.error = error;
        }

        @Override
        public String toString() {
            return "SimpleCabinetError{" +
                    "error='" + error + '\'' +
                    '}';
        }
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
