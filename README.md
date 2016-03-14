# oscp

https://drive.google.com/folderview?id=0B8BpJ_bHwXSKZ2ZiR1FQTHNoOEk&usp=sharing&tid=0B8BpJ_bHwXSKak0xRjdnaWFiYzg


#!/bin/sh

#input sharelink here. Example: https://drive.google.com/folderview?id=0B1g-MbiD2F6vdtOT92b3MoerO&usp=sharing
SHARELINK="https://drive.google.com/folderview?id=0B8BpJ_bHwXSKZ2ZiR1FQTHNoOEk&usp=sharing"
DESTINATION="/full/path/to/folder"
# Change following to false when you don't want to delete files when they are missing from google drive. This can
REMOVEFILES=true 

# Begin code

download () {
	url=$1
	folder=$2
	changed=$3

	wgetoutput="`wget --no-check-certificate -qO- $url 2>&1`"
	mkdir -p "$folder"
	commands="$(echo "$wgetoutput" | grep -Eo '\[,,\"(.*?)\",,,,,\"(.*?)\"')"
	missingfiles="$(find "$folder" -type f -depth 1 -print)"
	missingdirectories="$(find "$folder" -type d -depth 1 -print)"

	#Go to next

	subfolders="$(echo "$wgetoutput" | grep -Eo '\[,".*?\",\".*?folder' | cut -c 4- | cut -d\" -f 1)"
	IFS="
"
	for subfolder in $subfolders; do
		name=$(echo "$wgetoutput" | grep -Eo 'entry-'$subfolder'.*?</div></div><div class=\"flip-entry-title\">(.*?)</div>' | grep -Eo 'entry-title">.*?</div>$' | cut -c 14- | sed 's/<\/div>//')
		newdest="$2/$name"
		escapedfile="$(echo "$newdest" | sed -e 's/[]\$*.^|[]/\\&/g')"
		missingdirectories=$(echo "$missingdirectories" | sed -e "s@$escapedfile@@g" | sed '/^$/d')
		output=$(download "https://drive.google.com/folderview?id=$subfolder&usp=sharing" "$newdest" $changed)
		changed=$output
	done

	#Download files
	echo "Downloading for $folder..." 1>&2;
	for line in $commands; do
		id=$(echo "$line" | grep -Eio '\"[0-9a-z]+-[0-9a-z]+\"' | cut -c 2- | sed s'/.$//')
		name=$(echo "$line" | sed -e 's/\[,,\"//' | sed s/\".*//'')
		file="$folder/$name"
		cmd=$(echo "wget --no-check-certificate -nc -q --no-cookies -O \"$file\" \"https://docs.google.com/uc?export=download&id="$id"\"")
		eval "$cmd"
		commandresult=$?
		if [ "$commandresult" -eq 0 ]; then 
			echo "Downloaded: $file" 1>&2;
			changed=$(($changed + 1))
		else 
			echo "Skipped (Already exists or error): $file" 1>&2;
		fi
		escapedfile=$(echo "$file" | sed -e 's/[]@$*.^|[]/\\&/g')
		missingfiles=$(echo "$missingfiles" | sed 's@'$escapedfile'@@g' | sed '/^$/d')
	done
	echo "Finished downloading!" 1>&2;

	#Remove missing files
	if [ $REMOVEFILES = true ]; then
		echo "Checking files to remove from $folder..." 1>&2;
		i=0
		for line in $missingfiles; do
				echo "Removing file: $line" 1>&2;
				rm -f "$line"
				changed=$(($changed + 1))
		done
		for line in $missingdirectories; do
				echo "Removing directory: $line" 1>&2;
				rm -rf "$line"
				changed=$(($changed + 1))
		done
		echo "Finished scan!" 1>&2;
	fi

	echo $changed
}

result=$(download "$SHARELINK" "$DESTINATION" 0)
echo "Changed: $result files/folders"
if [ $result -ne 0 ]; then
	echo "Sync made changes to disk!"
fi
