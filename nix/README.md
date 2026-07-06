# Nix Flake Usage

## Run

```bash
nix run github:jtjones09/grabbr-hops

# With params
nix run github:jtjones09/grabbr-hops -- --help

```

## Home-manager module

Add input:

```nix
inputs = {
    hops.url = "github:jtjones09/grabbr-hops";
}
```

Optional: add [our binary cache](https://app.cachix.org/cache/lan-mouse) to allow a faster package install.

```nix
nixConfig = {
    extra-substituters = [
        "https://lan-mouse.cachix.org/"
    ];
    extra-trusted-public-keys = [
      "lan-mouse.cachix.org-1:KlE2AEZUgkzNKM7BIzMQo8w9yJYqUpor1CAUNRY6OyM="
    ];
};
```

Enable hops:

``` nix
{
  inputs,
  ...
}: {
  # Add the Home Manager module
  imports = [inputs.hops.homeManagerModules.default];

  programs.hops = {
    enable = true;
    # systemd = false;
    # package = inputs.hops.packages.${pkgs.stdenv.hostPlatform.system}.default
    # Optional configuration in nix syntax, see config.toml for available options
    # settings = { };
    };
  };
}

```
