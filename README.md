# Writing Shellcode with MSVC

An example of how to write shellcode with the MSVC C compiler!
[Follow along with the blog](https://amethyst.systems/blog/posts/shellcoding-with-msvc/).

## Building

All the various subprojects will trigger builds when the main project is built and run.

```
> mkdir build
> cd build
> cmake ../
> cmake --build ./ --config Release
```

## Testing

Once built, you can run the shellcode test. Don't worry, it's just
[Desktop Pet](https://github.com/Adrianotiger/desktopPet). I would hope you still at
least read the contents of the payload before running it.

```
> ctest -C Release
```
