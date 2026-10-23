.PHONY: all backend examples clean test

all: backend examples

backend:
	$(MAKE) -C backend

examples:
	$(MAKE) -C examples

clean:
	$(MAKE) -C backend clean
	$(MAKE) -C examples clean

test: all
	python3 -m pytest tests/ -v
