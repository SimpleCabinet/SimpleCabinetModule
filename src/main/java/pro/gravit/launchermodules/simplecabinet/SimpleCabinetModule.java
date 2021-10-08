package pro.gravit.launchermodules.simplecabinet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.modules.LauncherInitContext;
import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launcher.modules.LauncherModuleInfo;
import pro.gravit.launcher.modules.events.PreGsonPhase;
import pro.gravit.launchermodules.simplecabinet.auth.SimpleCabinetAuthCoreProvider;
import pro.gravit.launchermodules.simplecabinet.commands.SimpleCabinetCommand;
import pro.gravit.launchserver.auth.AuthProviderPair;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.modules.events.LaunchServerFullInitEvent;
import pro.gravit.utils.Version;
import pro.gravit.utils.helper.IOHelper;

import java.io.IOException;
import java.nio.file.Path;

/*
  Please change package and class name for you!
 */
public class SimpleCabinetModule extends LauncherModule {
    private transient Logger logger = LogManager.getLogger();
    private boolean registeredProviders = false;
    public SimpleCabinetModule() {
        super( new LauncherModuleInfo("SimpleCabinetModule", Version.of(1,0,0), new String[]{ "LaunchServerCore" }) );
    }

    public Path getDefaultJwtTokenPath(AuthProviderPair pair) {
        Path path = modulesConfigManager.getModuleConfigDir(moduleInfo.name).resolve(String.format("%s.jwt.key", pair.name));
        try {
            IOHelper.createParentDirs(path);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return path;
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::preConfigGson, PreGsonPhase.class);
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
    }

    public void finish(LaunchServerFullInitEvent event) {
        event.server.commandHandler.registerCommand("cabinet", new SimpleCabinetCommand(event.server, this));
    }

    public void preConfigGson(PreGsonPhase preGsonPhase) {
        if(!registeredProviders) {
            AuthCoreProvider.providers.register("simplecabinet", SimpleCabinetAuthCoreProvider.class);
            registeredProviders = true;
        }
    }
}
