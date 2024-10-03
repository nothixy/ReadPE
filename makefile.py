import powermake


def on_build(config: powermake.Config):
    files = powermake.get_files("**/*.c")

    config.add_includedirs("./")
    config.add_c_cpp_flags("-Weverything")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)


powermake.run("readpe_test", build_callback=on_build)
