package pro.gravit.launchermodules.simplecabinet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.modules.LauncherInitContext;
import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launcher.modules.LauncherModuleInfo;
import pro.gravit.launcher.modules.events.PreGsonPhase;
import pro.gravit.launchermodules.simplecabinet.auth.SimpleCabinetAuthCoreProvider;
import pro.gravit.launchserver.auth.core.AuthCoreProvider;
import pro.gravit.launchserver.modules.events.LaunchServerFullInitEvent;
import pro.gravit.utils.Version;

/*
  Please change package and class name for you!
 */
public class SimpleCabinetModule extends LauncherModule {
    private transient Logger logger = LogManager.getLogger();
    private boolean registeredProviders = false;
    public SimpleCabinetModule() {
        super( new LauncherModuleInfo("SimpleCabinetModule", Version.of(1,0,0), new String[]{ "LaunchServerCore" }) );
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::preConfigGson, PreGsonPhase.class);
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
    }

    public void finish(LaunchServerFullInitEvent event) {
        logger.info("Hello World!");
    }

    public void preConfigGson(PreGsonPhase preGsonPhase) {
        if(!registeredProviders) {
            AuthCoreProvider.providers.register("simplecabinet", SimpleCabinetAuthCoreProvider.class);
            registeredProviders = true;
        }
    }
}
