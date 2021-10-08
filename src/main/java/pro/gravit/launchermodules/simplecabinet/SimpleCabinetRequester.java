package pro.gravit.launchermodules.simplecabinet;

import com.google.gson.JsonElement;
import pro.gravit.launcher.Launcher;
import pro.gravit.launchserver.helper.HttpHelper;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;

public class SimpleCabinetRequester {
    public final String baseUrl;
    private transient final HttpClient httpClient = HttpClient.newBuilder().build();

    public SimpleCabinetRequester(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public static class SimpleCabinetErrorHandler<T> implements HttpHelper.HttpJsonErrorHandler<T, SimpleCabinetError> {
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

    public <T> SimpleCabinetErrorHandler<T> makeEH(Class<T> clazz) {
        return new SimpleCabinetErrorHandler<>(clazz);
    }

    public <T> HttpRequest get(String url, String token) {
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

    public <T> HttpRequest post(String url, T request, String token) {
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

    public <T> HttpHelper.HttpOptional<T, SimpleCabinetError> send(HttpRequest request, Class<T> clazz) throws IOException {
        return HttpHelper.send(httpClient, request, makeEH(clazz));
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
}
