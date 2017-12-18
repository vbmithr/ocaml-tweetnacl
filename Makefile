all:
	jbuilder build @install @runtest-tweetnacl

clean:
	rm -rf _build
