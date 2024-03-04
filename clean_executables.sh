mkdir -p ./executables_save

cp ./executables/*.exe ./executables_save/ 2>/dev/null || :
cp ./executables/*.dll ./executables_save/ 2>/dev/null || :

cp ./executables/.gitkeep ./executables_save/

rm -rf ./executables

mv executables_save executables

rm certificate* 2>/dev/null || :
rm resource* 2>/dev/null || :