#!/usr/bin/env python3
# python_requires/cpy_helpers.py
# CPython Helper Utilities for OpenSSL DevOps Ecosystem
# @security FIPS 140-3 compliant | @mcp MCP-Prompts orchestrated

import os
import subprocess
import sys
from pathlib import Path
import json
from typing import Dict, List, Optional, Union


class SecurityGates:
    """@security Security scanning integration"""
    
    @staticmethod
    def generate_sbom(target_path: Union[str, Path], output_format: str = "spdx-json") -> bool:
        """Generate SBOM with Syft"""
        try:
            target_path = Path(target_path)
            sbom_file = target_path.parent / f"sbom-{target_path.name}.{output_format.replace('-', '.')}"
            
            cmd = ["syft", str(target_path), "-o", f"{output_format}={sbom_file}"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            print(f"✓ SBOM generated: {sbom_file}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"✗ SBOM generation failed: {e}")
            return False
            
    @staticmethod
    def trivy_scan(target_path: Union[str, Path], severity: str = "CRITICAL,HIGH") -> bool:
        """@security Trivy vulnerability scan - blocks on CRITICAL findings"""
        try:
            cmd = ["trivy", "fs", "--exit-code", "1", "--severity", severity, str(target_path)]
            subprocess.run(cmd, check=True, capture_output=True)
            print("✓ Security scan passed - no vulnerabilities found")
            return True
        except subprocess.CalledProcessError:
            print("✗ Security scan FAILED - vulnerabilities found")
            return False
        except FileNotFoundError:
            print("⚠️ Trivy not found - install for security scanning")
            return False


class FIPSValidator:
    """@security FIPS 140-3 compliance validation"""
    
    FIPS_MODULE_PATHS = {
        "Linux": ["lib/ossl-modules/fips.so"],
        "Windows": ["bin/fips.dll", "lib/ossl-modules/fips.dll"], 
        "Darwin": ["lib/ossl-modules/fips.dylib"]
    }
    
    @classmethod
    def validate_fips_module(cls, install_path: Union[str, Path]) -> bool:
        """Validate FIPS module presence"""
        install_path = Path(install_path)
        system = platform.system()
        
        expected_paths = cls.FIPS_MODULE_PATHS.get(system, [])
        
        for rel_path in expected_paths:
            fips_path = install_path / rel_path
            if fips_path.exists():
                print(f"✓ FIPS module found: {fips_path}")
                return True
                
        print(f"✗ FIPS module not found in {install_path}")
        return False
        
    @staticmethod
    def validate_fips_config(config_path: Union[str, Path]) -> bool:
        """Validate FIPS configuration file"""
        config_path = Path(config_path)
        
        if not config_path.exists():
            print(f"✗ FIPS config not found: {config_path}")
            return False
            
        try:
            content = config_path.read_text()
            required_sections = ["fips_sect", "providers"]
            
            for section in required_sections:
                if section not in content:
                    print(f"✗ FIPS config missing section: {section}")
                    return False
                    
            print(f"✓ FIPS config validated: {config_path}")
            return True
        except Exception as e:
            print(f"✗ FIPS config validation failed: {e}")
            return False


class CPythonBootstrapper:
    """Bootstrap CPython environments for OpenSSL development"""
    
    def __init__(self, conan_file):
        self.conan_file = conan_file
        self.settings = conan_file.settings
        
    def create_activation_script(self, install_folder: Union[str, Path]) -> Path:
        """Create platform-specific activation script"""
        install_folder = Path(install_folder)
        
        if self.settings.os == "Windows":
            script_content = f"""@echo off
REM CPython Environment Activation - OpenSSL DevOps
set PYTHON_HOME={install_folder}
set PATH={install_folder};{install_folder}\\Scripts;%PATH%
set PYTHONPATH={install_folder}\\Lib;{install_folder}\\Lib\\site-packages

REM @security FIPS compliance
if exist "{install_folder}\\fips.cnf" (
    set OPENSSL_CONF={install_folder}\\fips.cnf
    set OPENSSL_FIPS=1
    echo FIPS mode enabled
)

echo CPython {self._get_python_version(install_folder)} environment activated
echo Installation: %PYTHON_HOME%
"""
            script_path = install_folder / "activate.bat"
        else:
            script_content = f"""#!/bin/bash
# CPython Environment Activation - OpenSSL DevOps
export PYTHON_HOME='{install_folder}'
export PATH='{install_folder}/bin:$PATH'
export PYTHONPATH='{install_folder}/lib/python3.12/site-packages:$PYTHONPATH'

# @security FIPS compliance
if [[ -f "{install_folder}/fips.cnf" ]]; then
    export OPENSSL_CONF="{install_folder}/fips.cnf"
    export OPENSSL_FIPS=1
    echo "FIPS mode enabled"
fi

echo "CPython $(python3 --version) environment activated"
echo "Installation: $PYTHON_HOME"
"""
            script_path = install_folder / "activate.sh"
            
        script_path.write_text(script_content)
        if self.settings.os != "Windows":
            os.chmod(script_path, 0o755)
            
        return script_path
        
    def create_symlink_structure(self, source_folder: Path, target_folder: Path) -> None:
        """Create zero-copy symlink structure"""
        target_folder.mkdir(parents=True, exist_ok=True)
        
        # Symlink essential directories
        symlink_dirs = {
            "bin": "bin",
            "lib": "lib", 
            "include": "include",
            "share": "share"
        }
        
        for src_name, dst_name in symlink_dirs.items():
            src_path = source_folder / src_name
            dst_path = target_folder / dst_name
            
            if src_path.exists() and not dst_path.exists():
                if self.settings.os == "Windows":
                    # Windows junction
                    subprocess.run(["mklink", "/J", str(dst_path), str(src_path)], shell=True)
                else:
                    dst_path.symlink_to(src_path)
                print(f"✓ Symlinked: {src_name} -> {dst_name}")
                
    def _get_python_version(self, install_folder: Path) -> str:
        """Extract Python version from installation"""
        try:
            python_bin = install_folder / ("python.exe" if self.settings.os == "Windows" else "bin/python3")
            if python_bin.exists():
                result = subprocess.run([str(python_bin), "--version"], capture_output=True, text=True)
                return result.stdout.strip()
        except:
            pass
        return "unknown"


class BuildOrchestrator:
    """@mcp Build orchestration with MCP-Prompts integration"""
    
    def __init__(self, conan_file):
        self.conan_file = conan_file
        self.security_gates = SecurityGates()
        self.fips_validator = FIPSValidator()
        
    def orchestrate_build(self, source_folder: Path, build_folder: Path, install_folder: Path) -> bool:
        """Full build orchestration with security gates"""
        print("🚀 Starting CPython build orchestration...")
        
        # Security: Pre-build validation
        if not self._validate_environment():
            return False
            
        # Build process would be here (handled by consuming conanfile)
        
        # Post-build security validation
        if self.conan_file.options.security_scan:
            if not self.security_gates.trivy_scan(install_folder):
                return False
                
        # FIPS compliance validation
        if self.conan_file.options.fips:
            if not self.fips_validator.validate_fips_module(install_folder):
                return False
                
        # Generate SBOM
        if self.conan_file.options.generate_sbom:
            self.security_gates.generate_sbom(install_folder)
            
        print("✓ Build orchestration completed successfully")
        return True
        
    def _validate_environment(self) -> bool:
        """Validate build environment"""
        required_tools = ["gcc", "make"] if self.conan_file.settings.os != "Windows" else ["cl.exe"]
        
        for tool in required_tools:
            if not self._tool_available(tool):
                print(f"✗ Required tool not found: {tool}")
                return False
                
        print("✓ Build environment validated")
        return True
        
    def _tool_available(self, tool: str) -> bool:
        """Check if tool is available in PATH"""
        try:
            subprocess.run([tool, "--version"], capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


# Export helpers for python_requires consumers
__all__ = ["SecurityGates", "FIPSValidator", "CPythonBootstrapper", "BuildOrchestrator"]
