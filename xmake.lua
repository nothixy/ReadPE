-- INSTALLATION:
--    https://xmake.io/#/guide/installation
-- USAGE:
--     set the mode with command: `xmake f -m debug`
--     compile the code with command: `xmake`

add_rules("mode.debug", "mode.release")

set_policy("build.warning", true)
set_warnings("all", "extra")

rule("flags_extras")
    if is_mode("debug") then
        on_config(function(target)
            target:add("defines", "DEBUG")
        end)
    end

target("readpe")
    set_kind("static")
    add_files("src/*.c")
    add_includedirs("./", {public = true})
    add_rules("flags_extras")


target("readpe_test")
    add_files("main.c")
    add_includedirs("./", {public = true})
    add_rules("flags_extras")
    add_deps("readpe")