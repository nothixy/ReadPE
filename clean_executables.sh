mkdir -p ./executables_save

cp ./executables/*.exe ./executables_save/
cp ./executables/.gitkeep ./executables_save/

rm -rf ./executables

mv executables_save executables
