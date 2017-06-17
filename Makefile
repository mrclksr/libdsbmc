all:

readme: readme.mdoc
	groff -Tascii -m mdoc -P -cbdu readme.mdoc | sed '1,1d' > README

