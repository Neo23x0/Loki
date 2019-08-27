# -*- mode: python -*-

a = Analysis(['loki.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)

a.datas = list({tuple(map(str.upper, t)) for t in a.datas})
a.datas+=[('rules', 'rules', 'DATA')]
a.datas+=[('rules.key', 'rules.key', 'DATA')]


pyz = PYZ(a.pure)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='loki.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True , icon='loki.ico')
