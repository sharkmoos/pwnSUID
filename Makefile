VENV=autosuid_venv
INVENV = $(shell pip3 -V | grep $(VENV))
current_dir = $(shell pwd)

prereqs: venvcheck FORCE
	pip install -r requirements.txt

venv: FORCE
	python3 -m venv $(VENV)

docs:
	pdoc  --html ./src/autosuid.py --force

venvcheck:
ifeq ($(INVENV),)
	$(error You should only run this from within the venv. Use '. ./$(VENV)/bin/activate')
else
	@echo "venv check passed\n"
endif


test: FORCE venvcheck 
	py.test -v test/ 


FORCE:
