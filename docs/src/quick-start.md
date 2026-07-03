# Quick start

```nix
# flake.nix (system)
{
  inputs.envelope.url = "github:beardedeagle/envelope";
  outputs = { nixpkgs, envelope, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [ envelope.nixosModules.default ./configuration.nix ];
    };
  };
}
```

On macOS the module is `darwinModules.default` and the configuration is
identical (`nix-darwin.lib.darwinSystem { modules = [ envelope.darwinModules.default … ]; }`).

```nix
# configuration.nix (NixOS) — or darwin.nix (nix-darwin), same options
services.dotenvx = {
  enable = true;
  services.myapp = {
    envFiles  = [ ./secrets/.env.production ];   # encrypted; safe in repo + store
    execStart = "${pkgs.hello}/bin/hello --listen 127.0.0.1:8080";
    # key.file defaults to /var/lib/dotenvx/.env.keys (see provisioning)
  };
};

# The module only owns ExecStart + credentials. If the unit isn't defined
# by an upstream module, give it the basics yourself:
systemd.services.myapp = {
  wantedBy = [ "multi-user.target" ];
  serviceConfig.DynamicUser = true;   # own UID ⇒ own /proc environ boundary
};
```

Author secrets on your workstation as usual:

```console
$ dotenvx set DATABASE_URL 'postgres://…' -f secrets/.env.production
# commit secrets/.env.production; NEVER commit secrets/.env.keys
```

To compose ExecStart yourself (`execStart = null`):

```nix
systemd.services.myapp.serviceConfig.ExecStart = lib.mkForce
  "${config.services.dotenvx.wrappers.myapp} ${lib.getExe pkgs.hello} --transport stdio";
```
