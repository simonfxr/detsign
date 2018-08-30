#!/usr/bin/env python
# -*- coding: utf-8 -*-

from conans import ConanFile, CMake, tools
import os
import glob


class DetsignConan(ConanFile):
    name = "detsign"
    version = "0.0.1"
    github_org = "simonfxr"
    github_project = "detsign"
    description = "detsign - determinstic signing via passphrases"
    url = "https://github.com/simonfxr/detsign"
    homepage = "https://github.com/simonfxr/detsign"
    author = "Simon Reiser <simonfxr@gmail.com>"
    # Indicates License type of the packaged library
    license = "GPL2"

    # Packages the license for the conanfile.py
    exports = ["LICENSE.md"]

    # Remove following lines if the target lib does not use cmake.
    exports_sources = ["CMakeLists.txt"]
    generators = "cmake_find_package"

    # Options may need to change depending on the packaged library.
    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = "shared=False", "fPIC=True"

    # Custom attributes for Bincrafters recipe conventions
    source_subfolder = "."
    build_subfolder = "build_subfolder"

    # Use version ranges for dependencies unless there's a reason not to
    # Update 2/9/18 - Per conan team, ranges are slow to resolve.
    # So, with libs like zlib, updates are very rare, so we now use static version

    requires = ("libsodium/1.0.16@bincrafters/stable")

    def config_options(self):
        if self.settings.os == 'Windows':
            del self.options.fPIC

    def source(self):
        return

    def configure_cmake(self):
        cmake = CMake(self)
        cmake.definitions["BUILD_TESTS"] = False  # example
        if self.settings.os != 'Windows':
            cmake.definitions[
                'CMAKE_POSITION_INDEPENDENT_CODE'] = self.options.fPIC
        cmake.configure(build_folder=self.build_subfolder)
        return cmake

    def build(self):
        cmake = self.configure_cmake()
        cmake.build()

    def package(self):
        self.copy(pattern="LICENSE", dst="licenses", src=self.source_subfolder)
        cmake = self.configure_cmake()
        cmake.install()
        # If the CMakeLists.txt has a proper install method, the steps below may be redundant
        # If so, you can just remove the lines below
        include_folder = os.path.join(self.source_subfolder, "include")
        self.copy(pattern="*", dst="include", src=include_folder)
        self.copy(pattern="*.dll", dst="bin", keep_path=False)
        self.copy(pattern="*.lib", dst="lib", keep_path=False)
        self.copy(pattern="*.a", dst="lib", keep_path=False)
        self.copy(pattern="*.so*", dst="lib", keep_path=False)
        self.copy(pattern="*.dylib", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
