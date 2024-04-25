# Pre-existing archives:
# - packages.gz
#     - Listing of all packages separated by line break.
# - pkgbase.gz
#     - Listing of all package bases separated by line break.
# - users.gz
#     - Listening of all users separated by line break.

# Metadata archives:
# - packages-meta-v1.json.gz
#     - A complete `type=search` formatted JSON package archive.
# - packages-meta-ext-v1.json.gz
#     - A complete `type=multiinfo` formatted JSON package archive.


# curl -s https://aur.archlinux.org/packages.gz | gunzip

# curl -s https://aur.archlinux.org/packages-meta-v1.json.gz | gunzip

curl -s https://aur.archlinux.org/packages-meta-ext-v1.json.gz | gunzip

# no CVE API?