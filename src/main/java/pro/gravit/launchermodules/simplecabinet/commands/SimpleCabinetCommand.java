package pro.gravit.launchermodules.simplecabinet.commands;

import pro.gravit.launchermodules.simplecabinet.SimpleCabinetModule;
import pro.gravit.launchserver.LaunchServer;
import pro.gravit.launchserver.command.Command;

public class SimpleCabinetCommand extends Command {
    private final SimpleCabinetModule module;

    public SimpleCabinetCommand(LaunchServer server, SimpleCabinetModule module) {
        super(server);
        this.module = module;
        this.childCommands.put("install", new InstallCommand(server, module));
    }

    @Override
    public String getArgsDescription() {
        return "[subcommand] [args]";
    }

    @Override
    public String getUsageDescription() {
        return "SimpleCabinet manager";
    }

    @Override
    public void invoke(String... args) throws Exception {
        invokeSubcommands(args);
    }
}
