{
  description = "Surf the net like the way it should be";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    goVersion = 24; # Change this to update the whole Go stack

    supportedSystems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forEachSupportedSystem = f:
      nixpkgs.lib.genAttrs supportedSystems (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [self.overlays.default];
          };
        in
          f pkgs
      );
  in {
    overlays.default = final: prev: {
      go = final."go_1_${toString goVersion}";
    };

    # Development shells
    devShells = forEachSupportedSystem (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [
          go # Go (version provided by the overlay)
          gotools # Additional Go tools like goimports, godoc, etc.
          golangci-lint
          gopls
          libpcap
        ];
        shellHook = ''
          export SHELL=$(which zsh)
        '';
      };
    });

    # Package derivation for building your Go binary.
    packages = forEachSupportedSystem (pkgs: {
      nyn = pkgs.buildGoModule {
        pname = "nyn";
        version = "0.0.1";
        src = pkgs.fetchFromGitHub {
          owner = "diredocks";
          repo = "nyn";
          rev = "v0.0.1"; # You can change this to a specific commit or tag
          hash = "sha256-cUHXhxAwaPNmh+mB8GCAw+Wk9HLvM2/kdPyEEWOxcGo="; # Replace after first build attempt
        };

        # Set this to an empty string initially, then run `nix build` and replace it with the generated hash
        vendorHash = "sha256-9+Ts7kaVGANAPiV4zsjMBFJF+g5ASTMcE/CAOmK2FpQ=";

        buildInputs = [pkgs.libpcap];

        meta = with pkgs.lib; {
          description = "Surf the net like the way it should be";
          license = licenses.mit;
          platforms = supportedSystems;
        };
      };
    });

    # App definition so you can run it via `nix run .#nyn`
    apps = forEachSupportedSystem (pkgs: {
      nyn = {
        type = "app";
        program = "${self.packages.${pkgs.system}.nyn}/bin/nyn";
      };
    });
  };
}
