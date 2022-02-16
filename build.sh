#!/usr/bin/env bash
if [ "$#" -lt 1 ]; then
  echo '参数缺失'
  exit 1
fi
if [ ! -f "$1.py" ]; then
  echo "文件不存在"
  exit 1
fi
mkdir .build/
cp slowDES.py slowSM4.py power_fake_toys.py "$1.py"  .build/
cd .build/
mv "$1.py" "__main__.py"
zip "$1.zip" ./*.py
mv "$1.zip" ../
cd -
rm -rf .build/
