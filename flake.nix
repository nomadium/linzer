{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    systems = {
      url = "github:nix-systems/default-linux";
      # XXX: should work, not tested yet on MacOS
      # url = "github:nix-systems/default";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    ruby-nix = {
      url = "github:inscapist/ruby-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    bundix = {
      url = "github:inscapist/bundix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    systems,
    ruby-nix,
    bundix,
  }: let
    eachSystem = f: nixpkgs.lib.genAttrs (import systems) (system: f system);

    makeRubyEnv = system: let
      pkgs = import nixpkgs {inherit system;};
      rubyNix = ruby-nix.lib pkgs;
      gemset = import ./gemset.nix;
      rubyEnv = rubyNix {
        name = "linzer-gems";
        inherit gemset;
        ruby = pkgs.ruby;
        gemConfig = pkgs.defaultGemConfig;
      };
    in {
      inherit pkgs rubyEnv;
    };
  in {
    devShells = eachSystem (system: let
      env = makeRubyEnv system;
    in {
      default = env.pkgs.mkShell {
        packages = [
          env.rubyEnv.ruby
          env.rubyEnv.env
        ];
      };
    });

    checks = eachSystem (system: let
      env = makeRubyEnv system;
    in {
      default = env.pkgs.stdenv.mkDerivation {
        name = "linzer-unit-tests";
        src = ./.;

        nativeBuildInputs = [
          env.rubyEnv.ruby
          env.rubyEnv.env
          env.pkgs.git
        ];

        doCheck = true;

        checkPhase = ''
          export HOME=$PWD/.nix-home
          mkdir -p $HOME
          rake
        '';

        installPhase = ''
          mkdir -p $out
          touch $out/done
        '';
      };
    });
  };
}
