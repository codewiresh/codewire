# A `standard` workspace disk (#5602), as the image volume a standard Pod
# mounts read-only at /image. Its context is the directory
# scripts/ci/images/workspace-disk.sh build writes: exactly image.raw,
# record.json, config.json and, for an image index, index.json.
FROM scratch
COPY . /
