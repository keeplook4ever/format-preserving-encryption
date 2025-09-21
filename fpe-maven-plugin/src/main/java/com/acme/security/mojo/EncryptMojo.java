package com.lennon.security.mojo;

import com.lennon.security.field.FieldProcessor;
import org.apache.maven.plugins.annotations.Mojo;

@Mojo(name = "encrypt")
public class EncryptMojo extends BaseMojo {

    @Override
    public void execute() {
        initEngine();
        FieldProcessor fp = buildProcessor();

        if (text == null || text.isEmpty()){
            getLog().info("No -Dtext provided, nothing to encrypt.");
            return;
        }
        String out = fp.encrypt(text);
        getLog().info("Encrypted: " + out);
        System.out.println(out);
    }
}
