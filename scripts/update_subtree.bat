cd ..
git subtree add --prefix depend/ion https://github.com/ionhaken/ion.git main --squash
git subtree pull --prefix depend/ion https://github.com/ionhaken/ion.git master --squash
