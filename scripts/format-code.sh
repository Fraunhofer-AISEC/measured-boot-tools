#!/usr/bin/env bash
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"

# Usage
#
# format-code [-u] [-s] [-n] [-q]
#
# All options can be combined. If no options given, all files in
# the directory will be formatted
#
# -u        Format unstaged, i.e. modified but not yet staged files
# -s        Format staged files
# -n        Format new, i.e. untracked files
# -q        Quiet, do not print modified files

ALL=1
UNSTAGED=0
STAGED=0
NEW=0
VERBOSE=-verbose

for arg in "$@"
do
    case $arg in
        -u|--unstaged) #
        ALL=0
        UNSTAGED=1
        shift
        ;;
	    -s|--staged) # O
        ALL=0
        STAGED=1
        shift
        ;;
        -n|--new)
        ALL=0
        NEW=1
        shift
        ;;
        -q|--quiet)
        VERBOSE=
        shift
        ;;
		*)
        OTHER_ARGUMENTS+=("$1")
        shift
        ;;
    esac
done

cd $ROOT_DIR

FILES_UNSTAGED=$(git diff --name-only -- '*.c' '*.h' | tr '\n' ' ')
FILES_STAGED=$(git diff --name-only --cached -- '*.c' '*.h' | tr '\n' ' ')
FILES_NEW=$(git ls-files --others --exclude-standard -- '*.c' '*.h')
FILES_ALL=$(find $ROOT_DIR -path "$ROOT_DIR/*/thirdparty" -prune -o -type f -regextype sed -regex ".*\(\.c\|\.h\)")
FILES=

if [ $ALL -eq 1 ]
then
    INFO="Formatting all files\n"
    FILES=$FILES_ALL
else
    if [ $UNSTAGED -eq 1 ]
    then
        INFO="Formatting unstaged files\n"
        FILES=${FILES}$FILES_UNSTAGED
    fi
    if [ $STAGED -eq 1 ]
    then
        INFO="${INFO}Formatting staged files\n"
        FILES=${FILES}${FILES_STAGED}
    fi
    if [ $NEW -eq 1 ]
    then
        INFO="${INFO}Formatting NEW files\n"
        FILES=${FILES}${FILES_NEW}
    fi
fi

if [ -n "$VERBOSE" ]
then
    printf "$INFO"
fi

if [ -z "$FILES" ]
then
    if [ -n "$VERBOSE" ]
    then
        echo "No files to be formatted"
    fi
else
    clang-format -i $VERBOSE -style=file $FILES
fi


