# Hashing

## Hashing some text
Run in terminal
```
echo -n "Hei TBB" | md5sum
echo -n "Hei TBD" | md5sum
```
See the difference

## Hashing a file
We have two small imagefiles, picture1.jpg and picture2.jpg. Source: Photo by Thomas Kelley on Unsplash.

picture1.jpg is almost identical to picture2.jpg, but picture2 has a changed pixel.

Show the pictures and then run in terminal
```
md5sum picture1.jpg
md5sum picture2.jpg
```
See the difference