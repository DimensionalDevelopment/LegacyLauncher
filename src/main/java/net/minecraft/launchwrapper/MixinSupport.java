package net.minecraft.launchwrapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.spongepowered.asm.mixin.MixinEnvironment;
import org.spongepowered.asm.mixin.Mixins;
import org.spongepowered.asm.mixin.transformer.MixinTransformer;
import org.spongepowered.asm.mixin.transformer.Proxy;
import org.spongepowered.asm.util.ReEntranceLock;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class MixinSupport {
    private static final Logger LOGGER = LogManager.getLogger("LaunchWrapper");
    private static MixinTransformer mixinTransformer = null;
    private static MixinEnvironment lastEnvironment = null;

    public static void onCachedClassLoad() throws ReflectiveOperationException {
        if (mixinTransformer == null) {
            for (IClassTransformer transformer : Launch.classLoader.getTransformers()) {
                if (transformer instanceof Proxy) {
                    Proxy mixinProxy = (Proxy) transformer;

                    Field transformerField = Proxy.class.getDeclaredField("transformer");
                    transformerField.setAccessible(true);
                    mixinTransformer = (MixinTransformer) transformerField.get(mixinProxy);
                }
            }
        }

        if (mixinTransformer == null) {
            return;
        }

        MixinEnvironment currentEnvironment = MixinEnvironment.getCurrentEnvironment();
        if (currentEnvironment != lastEnvironment || Mixins.getUnvisitedCount() > 0) {
            Field lockField = MixinTransformer.class.getDeclaredField("lock");
            lockField.setAccessible(true);
            ReEntranceLock lock = (ReEntranceLock) lockField.get(mixinTransformer);

            boolean locked = lock.push().check();
            try {
                if (!locked) {
                    LOGGER.info("Notifying Mixin of environment change " +
                                (lastEnvironment == null ? "null" : lastEnvironment.toString()) + " -> " +
                                (currentEnvironment == null ? "null" : currentEnvironment));
                    Method selectConfigsMethod = MixinTransformer.class.getDeclaredMethod("checkSelect", MixinEnvironment.class);
                    selectConfigsMethod.setAccessible(true);
                    selectConfigsMethod.invoke(mixinTransformer, currentEnvironment);
                }
            } finally {
                lock.pop();
            }
        }

        lastEnvironment = currentEnvironment;
    }
}
