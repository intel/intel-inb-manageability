rm -rf ./dist/inbm
earthly +build
earthly +build-deb
earthly +package
