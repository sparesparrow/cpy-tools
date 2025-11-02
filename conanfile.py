#!/usr/bin/env python3
from conan import ConanFile
from conan.errors import ConanException
from conan.tools.files import copy
import os
import platform


class SpareToolsBaseConan(ConanFile):
    """SpareTools Foundation - python_requires for OpenSSL ecosystem
    
    Provides utilities for CPython bootstrapping, security scanning,
    FIPS validation, and zero-copy symlink management.
    """
    
    name = "sparetools-base"
    version = "1.0.0"
    package_type = "python-require"  # Conan 2.x
    
    license = "Apache-2.0"
    author = "sparesparrow <devops@sparrow.ai>"
    url = "https://github.com/sparesparrow/sparetools"
    description = "Foundation utilities for SpareTools ecosystem (python_requires)"
    topics = ("cpython", "openssl", "fips", "security", "conan")
    
    # NO settings for python_requires - they don't have settings
    # NO options for python_requires - these should be in consuming recipes
    
    def export(self):
        """Export helper modules to Conan cache"""
        copy(self, "*.py", src=self.recipe_folder, dst=self.export_folder)
        copy(self, "python_requires/*.py", src=self.recipe_folder, dst=self.export_folder)
        copy(self, "extensions/*", src=self.recipe_folder, dst=self.export_folder)
        copy(self, "profiles/*", src=self.recipe_folder, dst=self.export_folder)
    
    # Provide static utility methods that consuming recipes can call
    @staticmethod
    def setup_python_environment(conanfile, cpython_dep=None):
        """Setup Python environment in consuming recipe
        
        Call this from consuming recipe's generate() method.
        
        Args:
            conanfile: The consuming ConanFile instance
            cpython_dep: Optional CPython dependency (will try to find if None)
        
        Returns:
            Python root path if found, None otherwise
        """
        if cpython_dep is None:
            cpython_dep = conanfile.dependencies.get("cpython-tool")
            if not cpython_dep:
                cpython_dep = conanfile.dependencies.get("cpython")
        
        if not cpython_dep:
            conanfile.output.info("No CPython dependency found, skipping Python environment setup")
            return None
            
        python_root = cpython_dep.package_folder
        
        # Setup environment variables
        conanfile.buildenv_info.define_path("PYTHON_ROOT", python_root)
        conanfile.runenv_info.define_path("PYTHON_ROOT", python_root)
        
        # Add Python bin to PATH
        if platform.system() == "Windows":
            python_bin = os.path.join(python_root, "Scripts")
        else:
            python_bin = os.path.join(python_root, "bin")
        
        if os.path.exists(python_bin):
            conanfile.buildenv_info.append_path("PATH", python_bin)
            conanfile.runenv_info.append_path("PATH", python_bin)
        
        conanfile.output.info(f"? Python environment setup: {python_root}")
        return python_root
    
    @staticmethod
    def setup_zero_copy_cpython(conanfile, cpython_dep=None, toolchain_name="cpython-toolchain"):
        """Setup zero-copy CPython symlink structure
        
        Call this from consuming recipe's generate() method.
        
        Args:
            conanfile: The consuming ConanFile instance
            cpython_dep: Optional CPython dependency (will try to find if None)
            toolchain_name: Name for the toolchain symlink in build folder
        
        Returns:
            Toolchain root path if successful, None otherwise
        """
        if cpython_dep is None:
            cpython_dep = conanfile.dependencies.get("cpython-tool")
            if not cpython_dep:
                cpython_dep = conanfile.dependencies.get("cpython")
        
        if not cpython_dep:
            conanfile.output.info("No CPython dependency, skipping zero-copy setup")
            return None
        
        cpython_cache = cpython_dep.package_folder
        build_folder = str(conanfile.folders.base_build)
        toolchain_root = os.path.join(build_folder, toolchain_name)
        
        # Create parent directory if needed
        os.makedirs(os.path.dirname(toolchain_root), exist_ok=True)
        
        # Remove existing symlink/file if present
        if os.path.exists(toolchain_root):
            if os.path.islink(toolchain_root):
                os.unlink(toolchain_root)
            elif os.path.isdir(toolchain_root):
                # If it's a directory, we can't safely remove it automatically
                conanfile.output.warn(f"Target exists and is a directory: {toolchain_root}")
                return None
        
        try:
            os.symlink(cpython_cache, toolchain_root, target_is_directory=True)
            conanfile.output.info(f"? Zero-copy setup: {toolchain_root} -> {cpython_cache}")
            return toolchain_root
        except OSError as e:
            # Fallback for Windows if symlink fails
            if platform.system() == "Windows":
                try:
                    cmd = f'mklink /J "{toolchain_root}" "{cpython_cache}"'
                    import subprocess
                    subprocess.run(cmd, shell=True, check=True)
                    conanfile.output.info(f"? Zero-copy setup (junction): {toolchain_root} -> {cpython_cache}")
                    return toolchain_root
                except Exception as junction_error:
                    conanfile.output.warn(f"Symlink/junction failed: {e} / {junction_error}")
            else:
                conanfile.output.warn(f"Symlink failed: {e}")
            return None
    
    @staticmethod
    def validate_fips(conanfile, install_folder):
        """FIPS validation helper
        
        Call this from consuming recipe's build() or package() method.
        
        Args:
            conanfile: The consuming ConanFile instance
            install_folder: Installation folder to validate
        
        Returns:
            True if FIPS module found, False otherwise
        """
        # Import from the exported module - try both relative and absolute paths
        try:
            from python_requires.cpy_helpers import FIPSValidator
        except ImportError:
            try:
                from .python_requires.cpy_helpers import FIPSValidator
            except ImportError:
                # Fallback: try to find it in the same directory structure
                import sys
                import os
                package_folder = os.path.dirname(os.path.abspath(__file__))
                python_requires_path = os.path.join(package_folder, "python_requires")
                if python_requires_path not in sys.path:
                    sys.path.insert(0, python_requires_path)
                from cpy_helpers import FIPSValidator
        
        validator = FIPSValidator()
        result = validator.validate_fips_module(install_folder)
        
        if not result:
            conanfile.output.warn(f"FIPS module validation failed for {install_folder}")
        else:
            conanfile.output.info(f"? FIPS module validated: {install_folder}")
        
        return result
    
    @staticmethod
    def run_security_scan(conanfile, target_path, severity="CRITICAL,HIGH", fail_on_findings=None):
        """Security scan helper
        
        Call this from consuming recipe's build() or package() method.
        
        Args:
            conanfile: The consuming ConanFile instance
            target_path: Path to scan
            severity: Severity levels to check (comma-separated)
            fail_on_findings: Whether to raise exception on findings (defaults to conf value)
        
        Returns:
            True if scan passed, False otherwise
        
        Raises:
            ConanException: If scan fails and fail_on_findings is True
        """
        # Import from the exported module - try both relative and absolute paths
        try:
            from python_requires.cpy_helpers import SecurityGates
        except ImportError:
            try:
                from .python_requires.cpy_helpers import SecurityGates
            except ImportError:
                # Fallback: try to find it in the same directory structure
                import sys
                import os
                package_folder = os.path.dirname(os.path.abspath(__file__))
                python_requires_path = os.path.join(package_folder, "python_requires")
                if python_requires_path not in sys.path:
                    sys.path.insert(0, python_requires_path)
                from cpy_helpers import SecurityGates
        
        gates = SecurityGates()
        
        # Generate SBOM first
        gates.generate_sbom(target_path)
        
        # Run Trivy scan
        scan_passed = gates.trivy_scan(target_path, severity=severity)
        
        if not scan_passed:
            # Check if we should fail
            if fail_on_findings is None:
                # Check conanfile conf for strict mode
                fail_on_findings = conanfile.conf.get("tools.sparetools:strict_security", default=True, check_type=bool)
            
            if fail_on_findings:
                raise ConanException(
                    f"Security scan failed - {severity} vulnerabilities found in {target_path}"
                )
        
        if scan_passed:
            conanfile.output.info(f"? Security scan passed: {target_path}")
        else:
            conanfile.output.warn(f"?? Security scan found vulnerabilities: {target_path}")
        
        return scan_passed
    
    @staticmethod
    def get_python_root(conanfile, cpython_dep=None):
        """Get Python root path from CPython dependency
        
        Helper method for consuming recipes to get Python root.
        
        Args:
            conanfile: The consuming ConanFile instance
            cpython_dep: Optional CPython dependency (will try to find if None)
        
        Returns:
            Python root path if found, None otherwise
        """
        if cpython_dep is None:
            cpython_dep = conanfile.dependencies.get("cpython-tool")
            if not cpython_dep:
                cpython_dep = conanfile.dependencies.get("cpython")
        
        if not cpython_dep:
            return None
        
        # Check for toolchain symlink first (zero-copy setup)
        cpython_cache = cpython_dep.package_folder
        build_folder = str(conanfile.folders.base_build)
        toolchain_path = os.path.join(build_folder, "cpython-toolchain")
        
        if os.path.exists(toolchain_path) and os.path.islink(toolchain_path):
            return toolchain_path
        
        return cpython_cache
