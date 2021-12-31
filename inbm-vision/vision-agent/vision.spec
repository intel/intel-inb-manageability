# -*- mode: python ; coding: utf-8 -*-

import sys
from os import path

block_cipher = None

site_packages = next(p for p in sys.path if 'site-packages' in p)

a = Analysis(['vision/vision.py'],
             pathex=['/src/vision-agent'],
             binaries=[],
             datas=[(path.join(site_packages,'xmlschema'), './xmlschema')],
             hiddenimports=['inbm_vision_lib.mqttclient', 'inbm_vision_lib'],
             hookspath=['../packaging/pyinstaller-hooks'],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
a.binaries = a.binaries - TOC([('libdb-5.3.so', None, None),
                               ('libgcrypt.so.20', None, None),
                               ('libgpg-error.so.0', None, None),
                               ('liblzma.so.5', None, None),
                               ('libreadline.so.7', None, None)])


pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='vision',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
