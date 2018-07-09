package net.minecraft.launchwrapper;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.*;
import java.nio.file.FileSystem;
import java.nio.file.*;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;
import java.util.zip.Adler32;

public class LaunchClassLoader extends URLClassLoader {
    private static final Logger LOGGER = LogManager.getLogger("LaunchWrapper");
    private static final Gson GSON = new GsonBuilder().create();

    public static final int BUFFER_SIZE = 1 << 12;
    private List<URL> sources;
    private ClassLoader parent = getClass().getClassLoader();

    private List<IClassTransformer> transformers = new ArrayList<>(2);
    private Map<String, Class<?>> cachedClasses = new ConcurrentHashMap<>();
    private Set<String> invalidClasses = new HashSet<>(1000);
    private Map<String, ClassNotFoundException> invalidClassExceptions = new HashMap<>(1000);

    private FileSystem cacheFileSystem;
    private CachedClassInfo cachedClassInfo;

    private Set<String> classLoaderExceptions = new HashSet<>();
    private Set<String> transformerExceptions = new HashSet<>();
    private Set<String> negativeResourceCache = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private Map<IClassTransformer, Long> transformerTimings;

    private IClassNameTransformer renameTransformer;

    private static final boolean DEBUG = Boolean.parseBoolean(System.getProperty("legacy.debugClassLoading", "false"));
    private static final boolean DEBUG_FINER = DEBUG && Boolean.parseBoolean(System.getProperty("legacy.debugClassLoadingFiner", "false"));
    private static final boolean DEBUG_SAVE = DEBUG && Boolean.parseBoolean(System.getProperty("legacy.debugClassLoadingSave", "false"));
    private static final boolean TIMINGS_ENABLED = Boolean.parseBoolean(System.getProperty("legacy.timings", "true"));
    private static File tempFolder = null;

    private boolean mixinLoaded = false;

    public LaunchClassLoader(URL[] sources) {
        super(sources, null);
        this.sources = new ArrayList<>(Arrays.asList(sources));

        // classloader exclusions
        addClassLoaderExclusion("java.");
        addClassLoaderExclusion("sun.");
        addClassLoaderExclusion("org.lwjgl.");
        addClassLoaderExclusion("org.apache.logging.");
        addClassLoaderExclusion("net.minecraft.launchwrapper.");

        // transformer exclusions
        addTransformerExclusion("javax.");
        addTransformerExclusion("argo.");
        addTransformerExclusion("org.objectweb.asm.");
        addTransformerExclusion("com.google.common.");
        addTransformerExclusion("org.bouncycastle.");
        addTransformerExclusion("net.minecraft.launchwrapper.injector.");

        initializeClassCacheSystem();

        if (DEBUG_SAVE) {
            int x = 1;
            tempFolder = new File(Launch.minecraftHome, "CLASSLOADER_TEMP");
            while (tempFolder.exists() && x <= 10) {
                tempFolder = new File(Launch.minecraftHome, "CLASSLOADER_TEMP" + x++);
            }

            if (tempFolder.exists()) {
                LOGGER.info("DEBUG_SAVE enabled, but 10 temp directories already exist, clean them and try again.");
                tempFolder = null;
            } else {
                LOGGER.info("DEBUG_SAVE Enabled, saving all classes to \"{}\"", tempFolder.getAbsolutePath().replace('\\', '/'));
                tempFolder.mkdirs();
            }
        }

        if (TIMINGS_ENABLED) {
            transformerTimings = new HashMap<>();
        }
    }

    private void initializeClassCacheSystem() {
        long startTime = System.nanoTime();

        File classCachesZip = new File(Launch.minecraftHome, "class_cache.zip");
        Map<String, String> env = new HashMap<>();
        env.put("create", "true");
        try {
            URI classCachesURI = classCachesZip.toURI();
            URI classCachesZipURI = new URI("jar:" + classCachesURI.getScheme(), classCachesURI.getPath(), null);
            cacheFileSystem = FileSystems.newFileSystem(classCachesZipURI, env, null);
        } catch (Throwable t) {
            if (classCachesZip.exists()) {
                LOGGER.error("Failed to read class caches", t);
                try {
                    classCachesZip.delete();
                    URI classCachesURI = classCachesZip.toURI();
                    URI classCahcesZipURI = new URI("jar:" + classCachesURI.getScheme(), classCachesURI.getPath(), null);
                    cacheFileSystem = FileSystems.newFileSystem(classCahcesZipURI, env, null);
                } catch (IOException | URISyntaxException e) {
                    throw new RuntimeException("Could not create cached_classes.zip", e);
                }
            } else {
                throw t instanceof RuntimeException ? (RuntimeException) t : new RuntimeException("Could not create cached_classes.zip", t);
            }
        }

        Path classInfoCacheFile = cacheFileSystem.getPath("cached_class_info.json");

        long result;
        try {
            Adler32 adler32 = new Adler32();

            File modsFolder = new File(Launch.minecraftHome, "mods");
            if (modsFolder.exists()) {
                for (File modFile : modsFolder.listFiles()) {
                    if (modFile.isFile()) {
                        adler32.update(Files.readAllBytes(modFile.toPath()));
                    }
                }

                result = adler32.getValue();
            } else {
                result = 0;
            }
        } catch (IOException e1) {
            throw new RuntimeException(e1);
        }
        long modsHash = result;

        try {
            if (Files.exists(classInfoCacheFile)) {
                try (Reader reader = new InputStreamReader(Files.newInputStream(classInfoCacheFile))) {
                    cachedClassInfo = GSON.fromJson(reader, CachedClassInfo.class);
                }

                if (modsHash != cachedClassInfo.modsHash) {
                    LOGGER.info("Mods hash changed, creating new cache: " + modsHash + " != " + cachedClassInfo.modsHash);
                    cachedClassInfo = null;
                }
            }
        } catch (Throwable t) {
            LOGGER.error("Failed to read cached_class_info.json", t);
        }

        if (cachedClassInfo == null) {
            cachedClassInfo = new CachedClassInfo();
            cachedClassInfo.modsHash = modsHash;
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // TODO: Doesn't always log message, log4j shutdown hook needs to run after this one
            try {
                Files.write(classInfoCacheFile, GSON.toJson(cachedClassInfo).getBytes(), StandardOpenOption.CREATE);
                cacheFileSystem.close();
                LOGGER.info("Saved caches successfully");
            } catch (Throwable t) {
                LOGGER.error("Failed to save caches", t);
            }
        }));

        LOGGER.info("Initialized cache system in {} ns", System.nanoTime() - startTime);
    }

    public void registerTransformer(String transformerClassName) {
        try {
            IClassTransformer transformer = (IClassTransformer) loadClass(transformerClassName).newInstance();
            transformers.add(transformer);
            if (transformer instanceof IClassNameTransformer && renameTransformer == null) {
                renameTransformer = (IClassNameTransformer) transformer;
            }

            if (TIMINGS_ENABLED) {
                transformerTimings.put(transformer, 0L);
            }
        } catch (Exception e) {
            LOGGER.error("A critical problem occurred registering the ASM transformer class {}", transformerClassName, e);
        }
    }

    @Override
    public Class<?> findClass(final String name) throws ClassNotFoundException {
        if (invalidClasses.contains(name)) {
            throw new ClassPreviouslyNotFoundException(name, invalidClassExceptions.get(name));
        }

        if (name.equals("org.spongepowered.asm.mixin.transformer.Proxy")) {
            mixinLoaded = true;
        }

        for (final String exception : classLoaderExceptions) {
            if (name.startsWith(exception)) {
                return parent.loadClass(name);
            }
        }

        if (cachedClasses.containsKey(name)) {
            return cachedClasses.get(name);
        }

        for (final String exception : transformerExceptions) {
            if (name.startsWith(exception)) {
                try {
                    final Class<?> clazz = super.findClass(name);
                    cachedClasses.put(name, clazz);
                    return clazz;
                } catch (ClassNotFoundException e) {
                    invalidClasses.add(name);
                    invalidClassExceptions.put(name, e);
                    throw e;
                }
            }
        }

        try {
            String transformedName = cachedClassInfo.transformedClassNames.get(name);
            if (transformedName == null) {
                transformedName = transformName(name);
                cachedClassInfo.transformedClassNames.put(name, transformedName);
            }

            String untransformedName = cachedClassInfo.untransformedClassNames.get(name);
            if (untransformedName == null) {
                untransformedName = untransformName(name);
                cachedClassInfo.untransformedClassNames.put(name, untransformedName);
            }

            final String fileName = untransformedName.replace('.', '/').concat(".class");
            URLConnection urlConnection = findCodeSourceConnectionFor(fileName);


            // Get class bytes
            byte[] untransformedClass = getClassBytes(untransformedName);

            // Get signers
            CodeSigner[] signers = null;
            if (untransformedName.indexOf('.') > -1 && !untransformedName.startsWith("net.minecraft.")) {
                if (urlConnection instanceof JarURLConnection) {
                    final JarFile jarFile = ((JarURLConnection) urlConnection).getJarFile();
                    if (jarFile != null && jarFile.getManifest() != null) {
                        signers = jarFile.getJarEntry(fileName).getCodeSigners();
                    }
                }
            }

            if (untransformedClass == null) {
                byte[] transformedClass = runTransformers(untransformedName, transformedName, untransformedClass);
                CodeSource codeSource = urlConnection == null ? null : new CodeSource(urlConnection.getURL(), signers);
                Class<?> clazz = defineClass(transformedName, transformedClass, 0, transformedClass.length, codeSource);
                cachedClasses.put(transformedName, clazz);
                return clazz;
            }

            // Calculate untransformed class hash
            Adler32 adler32 = new Adler32();
            adler32.update(untransformedClass);
            long untransformedClassHash = adler32.getValue();

            // Try getting the class from cache
            byte[] transformedClass = null;
            long transformedClassHash = cachedClassInfo.transformedClassHashes.getOrDefault(untransformedClassHash, 0L);

            if (transformedClassHash != 0) {
                try {
                    if (transformedClassHash == untransformedClassHash) {
                        transformedClass = untransformedClass;
                    } else {
                        transformedClass = getFromCache(transformedClassHash);
                    }

                    if (mixinLoaded) MixinSupport.onCachedClassLoad();
                } catch (Throwable t) {
                    LOGGER.error("Failed to read cached class {}", name, t);
                }
            }

            // Transform the class
            if (transformedClass == null) {
                transformedClass = runTransformers(untransformedName, transformedName, untransformedClass);

                // Calculate transformed class hash
                adler32.reset();
                adler32.update(transformedClass);
                transformedClassHash = adler32.getValue();

                try {
                    // Cache the transformed class
                    if (transformedClassHash != untransformedClassHash) {
                        saveToCache(transformedClassHash, transformedClass);
                    }
                    cachedClassInfo.transformedClassHashes.put(untransformedClassHash, transformedClassHash);
                } catch (Throwable t) {
                    LOGGER.error("Failed to saving class to cache {}", name, t);
                }
            }

            if (DEBUG_SAVE) {
                saveTransformedClass(transformedClass, transformedName);
            }

            final CodeSource codeSource = urlConnection == null ? null : new CodeSource(urlConnection.getURL(), signers);
            final Class<?> clazz = defineClass(transformedName, transformedClass, 0, transformedClass.length, codeSource);
            cachedClasses.put(transformedName, clazz);
            return clazz;
        } catch (Throwable e) {
            ClassNotFoundException classNotFoundException = new ClassNotFoundException(name, e);
            invalidClasses.add(name);
            invalidClassExceptions.put(name, classNotFoundException);
            if (DEBUG) {
                LOGGER.error("Exception encountered attempting classloading of {}", name, e);
            }
            throw classNotFoundException;
        }
    }

    private byte[] getFromCache(long hash) throws IOException {
        return Files.readAllBytes(cacheFileSystem.getPath(Long.toHexString(hash)));
    }

    private void saveToCache(long hash, byte[] data) throws IOException {
        Path path = cacheFileSystem.getPath(Long.toHexString(hash));

        if (!Files.exists(path)) {
            Files.write(path, data);
        }
    }

    private void saveTransformedClass(final byte[] data, final String transformedName) {
        if (tempFolder == null) {
            return;
        }

        final File outFile = new File(tempFolder, transformedName.replace('.', File.separatorChar) + ".class");
        final File outDir = outFile.getParentFile();

        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        if (outFile.exists()) {
            outFile.delete();
        }

        try {
            LOGGER.debug("Saving transformed class \"{}\" to \"{}\"", transformedName, outFile.getAbsolutePath().replace('\\', '/'));

            final OutputStream output = new FileOutputStream(outFile);
            output.write(data);
            output.close();
        } catch (IOException e) {
            LOGGER.warn("Could not save transformed class \"{}\"", transformedName, e);
        }
    }

    private String untransformName(final String name) {
        if (renameTransformer != null) {
            if (TIMINGS_ENABLED) {
                long startTime = System.nanoTime();
                String result = renameTransformer.unmapClassName(name);
                //noinspection SuspiciousMethodCalls (all IClassNameTransformers are IClassTransformers)
                transformerTimings.put((IClassTransformer) renameTransformer, transformerTimings.get(renameTransformer) + System.nanoTime() - startTime);
                return result;
            } else {
                return renameTransformer.unmapClassName(name);
            }
        }

        return name;
    }

    private String transformName(final String name) {
        if (renameTransformer != null) {
            if (TIMINGS_ENABLED) {
                long startTime = System.nanoTime();
                String result = renameTransformer.remapClassName(name);
                //noinspection SuspiciousMethodCalls (all IClassNameTransformers are IClassTransformers)
                transformerTimings.put((IClassTransformer) renameTransformer, transformerTimings.get(renameTransformer) + System.nanoTime() - startTime);
                return result;
            } else {
                return renameTransformer.remapClassName(name);
            }
        }

        return name;
    }

    private URLConnection findCodeSourceConnectionFor(final String name) {
        final URL resource = findResource(name);
        if (resource != null) {
            try {
                return resource.openConnection();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        return null;
    }

    private byte[] runTransformers(final String name, final String transformedName, byte[] basicClass) {
        if (DEBUG_FINER) {
            LOGGER.trace("Beginning transform of {{} ({})} Start Length: %d", name, transformedName, basicClass == null ? 0 : basicClass.length);
            for (final IClassTransformer transformer : transformers) {
                final String transName = transformer.getClass().getName();
                LOGGER.trace("Before Transformer {{} ({})} {}: %d", name, transformedName, transName, basicClass == null ? 0 : basicClass.length);
                long startTime = System.nanoTime();
                basicClass = transformer.transform(name, transformedName, basicClass);
                long timeTaken = System.nanoTime() - startTime;
                LOGGER.trace("After  Transformer {{} ({})} {}: %d (took %d ns)", name, transformedName, transName, basicClass == null ? 0 : basicClass.length, timeTaken);
                transformerTimings.put(transformer, transformerTimings.get(transformer) + timeTaken);
            }
            LOGGER.trace("Ending transform of {{} ({})} Start Length: %d", name, transformedName, basicClass == null ? 0 : basicClass.length);
        } else if (TIMINGS_ENABLED) {
            for (final IClassTransformer transformer : transformers) {
                long startTime = System.nanoTime();
                basicClass = transformer.transform(name, transformedName, basicClass);
                transformerTimings.put(transformer, transformerTimings.get(transformer) + System.nanoTime() - startTime);
            }
        } else {
            for (final IClassTransformer transformer : transformers) {
                basicClass = transformer.transform(name, transformedName, basicClass);
            }
        }
        return basicClass;
    }

    @Override
    public void addURL(final URL url) {
        super.addURL(url);
        sources.add(url);
    }

    public List<URL> getSources() {
        return sources;
    }

    public List<IClassTransformer> getTransformers() {
        return Collections.unmodifiableList(transformers);
    }

    public Map<IClassTransformer, Long> getTransformerTimings() {
        return TIMINGS_ENABLED ? Collections.unmodifiableMap(transformerTimings) : null;
    }

    public void addClassLoaderExclusion(String toExclude) {
        classLoaderExceptions.add(toExclude);
    }

    public void addTransformerExclusion(String toExclude) {
        transformerExceptions.add(toExclude);
    }

    public byte[] getClassBytes(String name) throws IOException {
        if (negativeResourceCache.contains(name)) {
            return null;
        }

        final String resourcePath = name.replace('.', '/').concat(".class");
        final URL classResource = findResource(resourcePath);

        if (classResource == null) {
            if (DEBUG) LOGGER.trace("Failed to find class resource {}", resourcePath);
            negativeResourceCache.add(name);
            return null;
        }

        if (DEBUG) LOGGER.trace("Loading class {} from resource {}", name, classResource.toString());

        return IOUtils.toByteArray(classResource.openStream());
    }

    public void clearNegativeEntries(Set<String> entriesToClear) {
        negativeResourceCache.removeAll(entriesToClear);
    }
}
