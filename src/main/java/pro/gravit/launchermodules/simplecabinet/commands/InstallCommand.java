package pro.gravit.launchermodules.simplecabinet.commands;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launchermodules.simplecabinet.SimpleCabinetModule;
import pro.gravit.launchermodules.simplecabinet.SimpleCabinetRequester;
import pro.gravit.launchermodules.simplecabinet.auth.SimpleCabinetAuthCoreProvider;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.auth.AuthProviderPair;
import pro.gravit.launchserver.command.Command;
import pro.gravit.utils.helper.IOHelper;

import java.net.URL;
import java.util.Base64;

public class InstallCommand extends Command {
    private final SimpleCabinetModule module;
    private transient final Logger logger = LogManager.getLogger();

    public InstallCommand(LaunchServer server, SimpleCabinetModule module) {
        super(server);
        this.module = module;
    }

    @Override
    public String getArgsDescription() {
        return "install SimpleCabinet";
    }

    @Override
    public String getUsageDescription() {
        return "[url] [token] (authId)";
    }

    @Override
    public void invoke(String... args) throws Exception {
        verifyArgs(args, 2);
        String baseUrl = args[0];
        String token = args[1];
        if(baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length()-1);
        }
        {
            new URL(baseUrl); // Test URL
        }
        AuthProviderPair pair = args.length > 2 ? server.config.getAuthProviderPair(args[2]) : server.config.getAuthProviderPair();
        if(pair == null) {
            logger.error("AuthId incorrect");
            return;
        }
        var requester = new SimpleCabinetRequester(baseUrl);
        var user = requester.send(requester.get("/auth/userinfo", token), SimpleCabinetAuthCoreProvider.SimpleCabinetUser.class).getOrThrow();
        logger.info("Logged in {}", user.getUsername());
        var status = requester.send(requester.get("/status/publicinfo", token), PublicStatusInfo.class).getOrThrow();
        var jwtKey = Base64.getDecoder().decode(status.jwtPublicKey);
        var path = module.getDefaultJwtTokenPath(pair);
        logger.info("Write SimpleCabinet Public key to {}", path.toString());
        IOHelper.write(path, jwtKey);
        var core = new SimpleCabinetAuthCoreProvider();
        core.baseUrl = baseUrl;
        core.adminJwtToken = token;
        core.jwtPublicKeyPath = path.toAbsolutePath().toString();
        core.init(server);
        pair.core.close();
        pair.core = core;
        pair.textureProvider = null;
        logger.info("SimpleCabinet installed");
    }

    public static record PublicStatusInfo(String jwtPublicKey) {
    }
}
