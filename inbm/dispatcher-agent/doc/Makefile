doc-init:
	pip install -r requirements.txt

html:
	epydoc --html --exclude=tests ../dispatcher ../mqttclient -o html

clean:
	rm -rf html