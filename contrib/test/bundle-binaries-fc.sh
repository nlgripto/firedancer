#!/bin/bash
# This script will take the path to build/ as an argument $1, create the needed .fc
# files alongside the binaries in a flat temporary directory, then create the final zip at $2.
set -e

build_dir="$1"
output_zip="$2"

# Ensure output_zip is an absolute path
output_zip="$(cd "$(dirname "$output_zip")"; pwd)/$(basename "$output_zip")"

# Create a temporary directory
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# Function to get the current Git commit hash
get_git_commit() {
    git rev-parse HEAD 2>/dev/null || echo "No git commit found"
}

# Get the current Git commit hash
commit_hash=$(get_git_commit)

# Create fuzzcorp.json in the temporary directory
cat > "$tmp_dir/fuzzcorp.json" <<EOL
{
  "commit": "$commit_hash"
}
EOL

# Loop through each architecture and compiler
for arch in haswell icelake; do
  for compiler in clang; do #aflgcc later
    target_dir="$build_dir/linux/$compiler/$arch/fuzz-test"
    
    # Copy binaries and create .fc files
    for target in "$target_dir"/*; do
      if [ -f "$target" ] && [ -x "$target" ]; then
        target_name=$(basename "$target")
        
        # Copy the fuzz target binary
        cp "$target" "$tmp_dir/${target_name}_${arch}"
        
        # Create the .fc file
        fc_file="$tmp_dir/${target_name}_${arch}.fc"
        cat > "$fc_file" <<EOL
{
  "fuzzTargetPath": "${target_name}_${arch}",
  "covTargetPath": "",
  "lineage": "${target_name}_${arch}",
  "corpusGroup": "$target_name",
  "architecture": {
    "base": "x86_64",
    "ext": ["$([ "$arch" == "haswell" ] && echo "avx2" || echo "avx512")"]
  }
}
EOL
      fi
    done

    # Copy library files
    if [ -d "$build_dir/lib" ]; then
      cp "$build_dir/lib/"*.so* "$tmp_dir/"
    else
      echo "Warning: $build_dir/lib not found. Skipping library copy."
    fi

  done # end compilers
done # end arch

# Create the zip file from the temporary directory
(cd "$tmp_dir" && zip -r "$output_zip" .)

echo "Fuzz targets, .fc files, and fuzzcorp.json generated and zipped successfully!"
echo "Output zip created at: $output_zip"