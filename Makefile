PIP=	pip3.8

letslambda.zip: letslambda.py requirements.txt
	@$(MAKE) clean
	mkdir package
	$(PIP) install --target=./package -r requirements.txt
	cd package ; zip -r ../$@ .
	zip $@ letslambda.py

clean:
	rm -rf package letslambda.zip
