mkdir ../../SnortUnified/
rm -rf ../../SnortUnified/*
cp -a * ../../SnortUnified/

tar -X exclude.txt -cvzf dist/SnortUnified_Perl.`date +%Y%m%d`.tgz ../../SnortUnified/
