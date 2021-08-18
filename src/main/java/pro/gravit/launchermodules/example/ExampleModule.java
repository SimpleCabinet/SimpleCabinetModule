package pro.gravit.launchermodules.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pro.gravit.launcher.modules.LauncherInitContext;
import pro.gravit.launcher.modules.LauncherModule;
import pro.gravit.launcher.modules.LauncherModuleInfo;
import pro.gravit.launchserver.modules.events.LaunchServerFullInitEvent;
import pro.gravit.utils.Version;

/*
  Please change package and class name for you!
 */
public class ExampleModule extends LauncherModule {
    private transient Logger logger = LogManager.getLogger();
    public ExampleModule() {
        super( new LauncherModuleInfo("ExampleModule", Version.of(1,0,0), new String[]{ "LaunchServerCore" }) );
    }

    @Override
    public void init(LauncherInitContext initContext) {
        registerEvent(this::finish, LaunchServerFullInitEvent.class);
    }

    public void finish(LaunchServerFullInitEvent event) {
        logger.info("Hello World!");
    }
}
