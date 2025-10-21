import os
import sys
import subprocess
import uuid
import tempfile
from pathlib import Path
import pefile

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

def extract_exe_metadata(exe_path):
    """
    Safely extract product name, version, and company from the EXE's version info.
    Falls back to filename / defaults if data is missing.
    """
    product_name = Path(exe_path).stem
    manufacturer = "Unknown"
    product_version = "1.0.0.0"

    try:
        pe = pefile.PE(exe_path)
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for fileinfo in pe.FileInfo:
                if getattr(fileinfo, "Key", b"") == b"StringFileInfo":
                    for st in getattr(fileinfo, "StringTable", []):
                        entries = getattr(st, "entries", {})
                        if entries:
                            product_name = entries.get(b"ProductName", product_name.encode()).decode(errors="ignore")
                            manufacturer = entries.get(b"CompanyName", manufacturer.encode()).decode(errors="ignore")
                            product_version = entries.get(b"ProductVersion", product_version.encode()).decode(errors="ignore")
        product_version = product_version.replace(",", ".")
        if product_version.count(".") > 3:
            product_version = ".".join(product_version.split(".")[:4])
    except Exception:
        pass

    return product_name, manufacturer, product_version


def get_silent_args(exe_path):
    """
    Determine silent install arguments for known EXE installers.
    Currently supports 7-Zip.
    """
    exe_name = exe_path.name.lower()
    if "7z" in exe_name:
        # 7-Zip installer: /S silent, /D=<install folder>
        return '/S /D=&quot;[INSTALLFOLDER]&quot;'
    # Default fallback: just /S
    return "/S"


def generate_wxs(exe_path, arch, product_name, manufacturer, version, product_code, upgrade_code):
    """
    Generate WiX XML for wrapping the EXE and installing it to INSTALLFOLDER.
    """
    silent_args = get_silent_args(exe_path)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="{product_code}"
           Name="{product_name}"
           Language="1033"
           Version="{version}"
           Manufacturer="{manufacturer}"
           UpgradeCode="{upgrade_code}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Platform="{arch}" />
    <MediaTemplate EmbedCab="yes" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="{product_name}">
          <Component Id="MainExecutable" Guid="{uuid.uuid4()}">
            <File Id="InstallerExe" Name="{exe_path.name}" Source="{exe_path}" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id="MainFeature" Title="{product_name}" Level="1">
      <ComponentRef Id="MainExecutable" />
    </Feature>

    <!-- Run installer silently -->
    <CustomAction Id="RunInstaller" FileKey="InstallerExe" ExeCommand="{silent_args}" Execute="deferred" Return="ignore" Impersonate="no" />
    <InstallExecuteSequence>
      <Custom Action="RunInstaller" After="InstallFiles">NOT Installed</Custom>
    </InstallExecuteSequence>

    <!-- Uninstall -->
    <CustomAction Id="RemoveInstaller" FileKey="InstallerExe" ExeCommand="/S /D=&quot;[INSTALLFOLDER]&quot;" Execute="deferred" Return="ignore" Impersonate="no" />
    <InstallExecuteSequence>
      <Custom Action="RemoveInstaller" Before="RemoveFiles">REMOVE="ALL"</Custom>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""


def sign_msi(msi_path, cert_path=None, cert_password=None, timestamp_url="http://timestamp.digicert.com"):
    """Digitally sign the MSI using signtool.exe, if a certificate is supplied."""
    if not cert_path:
        print(f"[!] No certificate supplied — skipping signing. {msi_path.name} will show as 'Unknown Publisher'.")
        return

    print(f"[*] Signing {msi_path.name} with certificate...")
    cmd = [
        "signtool", "sign",
        "/f", str(cert_path),
        "/fd", "sha256",
        "/tr", timestamp_url,
        "/td", "sha256",
        str(msi_path)
    ]

    if cert_password:
        cmd.insert(cmd.index("/fd"), "/p")
        cmd.insert(cmd.index("/fd"), cert_password)

    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Signed: {msi_path}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Signing failed: {e}. MSI remains unsigned.")


def build_msi(exe_path, output_dir, arch, cert_path=None, cert_password=None):
    """Compile, link, and optionally sign an MSI for the given architecture."""
    exe_path = Path(exe_path).resolve()
    product_name, manufacturer, version = extract_exe_metadata(exe_path)
    output_msi = Path(output_dir) / f"{product_name}_{arch}.msi"

    product_code = str(uuid.uuid4()).upper()
    upgrade_code = str(uuid.uuid4()).upper()

    temp_dir = Path(tempfile.mkdtemp(prefix=f"exe2msi_{arch}_"))
    wxs_path = temp_dir / f"Product_{arch}.wxs"

    wxs_content = generate_wxs(exe_path, arch, product_name, manufacturer, version, product_code, upgrade_code)
    wxs_path.write_text(wxs_content, encoding="utf-8")

    wixobj = temp_dir / f"Product_{arch}.wixobj"
    print(f"[*] Compiling WiX for {arch}...")
    subprocess.run(["candle", "-nologo", "-out", str(wixobj), str(wxs_path)], check=True)

    print(f"[*] Linking MSI for {arch}...")
    subprocess.run(["light", "-nologo", "-out", str(output_msi), str(wixobj)], check=True)

    sign_msi(output_msi, cert_path, cert_password)
    return output_msi


def main():
    if len(sys.argv) < 3:
        print("Usage: python exe_to_msi.py <input_installer.exe> <output_folder> [cert.pfx] [cert_password]")
        sys.exit(1)

    exe_path = sys.argv[1]
    output_folder = Path(sys.argv[2]).resolve()
    cert_path = Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None
    cert_password = sys.argv[4] if len(sys.argv) > 4 else None

    output_folder.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building MSI wrappers for: {exe_path}")
    build_msi(exe_path, output_folder, "x86", cert_path, cert_password)
    build_msi(exe_path, output_folder, "x64", cert_path, cert_password)

    print("\n✅ Done. Both x86 and x64 MSI files are built.")
    if not cert_path:
        print("⚠️  No certificate provided — both MSIs are unsigned and will show 'Unknown Publisher'.")


if __name__ == "__main__":
    main()
