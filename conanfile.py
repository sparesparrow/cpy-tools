#!/usr/bin/env python3
# conanfile.py - CPython Tools python_requires
# Foundation utilities for OpenSSL DevOps ecosystem
# @security FIPS 140-3 compliant | @mcp MCP-Prompts orchestrated

from conan import ConanFile
from conan.tools.env import Environment
from conan.tools.files import copy, save, load, rmdir
from conan.tools.scm import Git
import os
import platform
import subprocess
import json
from pathlib import Path


class CpyToolsConan(ConanFile):
    """CPython Tools - python_requires for OpenSSL ecosystem
    
    Provides:
    - Security gates integration (SBOM, Trivy, CodeQL)
    - Bootstrap utilities
    - Build orchestration helpers
    - FIPS 140-3 compliance validation
    - Cross-platform Python environment management
    """
    
    name = "cpy-tools"
    version = "1.0.0"
    
    # Package metadata
    license = "Apache-2.0"
    author = "sparesparrow <devops@sparrow.ai>"
    url = "https://github.com/sparesparrow/cpy-tools"
    description = "CPython tools and utilities - python_requires foundation for OpenSSL DevOps ecosystem"
    topics = ("cpython", "openssl", "fips", "security", "conan", "devops")
    
    # Configuration
    options = {
        "fips": [True, False],
        "security_scan": [True, False], 
        "generate_sbom": [True, False]
    }
    default_options = {
        "fips": True,
        "security_scan": True,
        "generate_sbom": True
    }
    
    # No settings for python_requires - this is pure utility
    settings = "os", "arch", "compiler", "build_type"
    
    @property
    def _is_fips_required(self):
        return bool(self.options.fips)
        
    @property  
    def _platform_key(self):
        """Generate platform key for artifacts"""
        return f"{self.settings.os}-{self.settings.arch}".lower()
    
    def export(self):
        """Export python_requires helpers"""
        self.copy("*.py", dst=".", src="python_requires")
        self.copy("*.sh", dst=".", src="scripts")
        self.copy("*.yml", dst=".", src="workflows")
        
    def python_requires(self):
        """Make this package available as python_requires"""
        pass
        
    def security_scan(self, target_path):
        """@security Integrate Syft SBOM + Trivy scan"""
        if not self.options.security_scan:
            self.output.info("Security scanning disabled")
            return True
            
        results = {"sbom": False, "trivy": False}
        
        # @security SBOM generation with Syft
        if self.options.generate_sbom:
            try:
                sbom_file = f"{target_path}/sbom-{self._platform_key}.spdx.json"
                cmd = ["syft", target_path, "-o", f"spdx-json={sbom_file}"]
                subprocess.run(cmd, check=True, capture_output=True)
                results["sbom"] = True
                self.output.info(f"✓ SBOM generated: {sbom_file}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                self.output.warning(f"SBOM generation failed: {e}")
                
        # @security Trivy vulnerability scan
        try:
            cmd = ["trivy", "fs", "--exit-code", "1", "--severity", "CRITICAL,HIGH", target_path]
            subprocess.run(cmd, check=True, capture_output=True)
            results["trivy"] = True
            self.output.info("✓ Security scan passed - no CRITICAL/HIGH vulnerabilities")
        except subprocess.CalledProcessError:
            self.output.error("✗ Security scan FAILED - CRITICAL/HIGH vulnerabilities found")
            if not self.conf.get("tools.system.package_manager:mode") == "development":
                raise
        except FileNotFoundError:
            self.output.warning("Trivy not found - install for security scanning")
            
        return all(results.values())
        
    def validate_fips_compliance(self, install_folder):
        """@security Validate FIPS 140-3 compliance"""
        if not self._is_fips_required:
            return True
            
        self.output.info("Validating FIPS 140-3 compliance...")
        
        # Check for FIPS module presence
        fips_paths = [
            os.path.join(install_folder, "lib", "ossl-modules", "fips.so"),
            os.path.join(install_folder, "lib", "ossl-modules", "fips.dll"),
            os.path.join(install_folder, "lib", "ossl-modules", "fips.dylib")
        ]
        
        fips_found = any(os.path.exists(path) for path in fips_paths)
        if not fips_found:
            self.output.error("✗ FIPS module not found - FIPS compliance validation failed")
            return False
            
        self.output.info("✓ FIPS module validation passed")
        return True
        
    def bootstrap_environment(self, install_folder):
        """Bootstrap Python environment with security validation"""
        self.output.info(f"Bootstrapping CPython environment in {install_folder}")
        
        # Create environment scripts
        if self.settings.os == "Windows":
            script_content = f"""@echo off
set PYTHON_HOME={install_folder}
set PATH={install_folder};{install_folder}\\Scripts;%PATH%
echo CPython environment activated
"""
            script_path = os.path.join(install_folder, "activate.bat")
        else:
            script_content = f"""#!/bin/bash
export PYTHON_HOME='{install_folder}'
export PATH='{install_folder}/bin:$PATH'
echo 'CPython environment activated'
"""
            script_path = os.path.join(install_folder, "activate.sh")
            
        save(self, script_path, script_content)
        if self.settings.os != "Windows":
            os.chmod(script_path, 0o755)
            
        # Validate installation
        python_bin = os.path.join(
            install_folder,
            "python.exe" if self.settings.os == "Windows" else "bin/python3"
        )
        
        if not os.path.exists(python_bin):
            raise Exception(f"Python binary not found: {python_bin}")
            
        # Test basic functionality
        try:
            result = subprocess.run(
                [python_bin, "-c", "import sys; print(f'Python {sys.version} ready')"],
                check=True, capture_output=True, text=True
            )
            self.output.info(f"✓ {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Python validation failed: {e}")
            
    def generate_build_report(self, build_folder):
        """Generate comprehensive build report for @cursor agents"""
        report = {
            "timestamp": self._get_timestamp(),
            "platform": self._platform_key,
            "fips_enabled": self._is_fips_required,
            "security_scan_enabled": bool(self.options.security_scan),
            "sbom_generated": bool(self.options.generate_sbom),
            "conan_version": self._get_conan_version(),
            "python_version": self._get_python_version()
        }
        
        report_path = os.path.join(build_folder, "cpy-tools-report.json")
        save(self, report_path, json.dumps(report, indent=2))
        
        self.output.info(f"✓ Build report generated: {report_path}")
        return report_path
        
    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().isoformat()
        
    def _get_conan_version(self):
        try:
            result = subprocess.run(["conan", "--version"], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "unknown"
            
    def _get_python_version(self):
        import sys
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
    def package_info(self):
        """Provide python_requires interface"""
        # Make helper methods available to consumers
        self.cpp_info.set_property("python_requires", "cpy-tools")
        
        # Environment setup for consumers
        if self._is_fips_required:
            self.buildenv_info.define("OPENSSL_FIPS", "1")
            self.buildenv_info.define("FIPS_MODULE_VERSION", self.version)
            
        # Security scan integration
        if self.options.security_scan:
            self.buildenv_info.define("CPY_SECURITY_SCAN", "1")
            
        self.output.info("✓ cpy-tools python_requires configured")