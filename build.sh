#!/bin/sh
# on an AWS cloud9
git clone https://github.com/rayba/letslambda.git
cd letslambda
python3 -m pip install --target=./ -r requirements.txt
zip -r letslambda.zip .
