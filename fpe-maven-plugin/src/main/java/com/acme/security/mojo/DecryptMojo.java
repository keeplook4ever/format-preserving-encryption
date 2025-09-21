package com.lennon.security.mojo;

import com.lennon.security.field.FieldProcessor;
import org.apache.maven.plugins.annotations.Mojo;

@Mojo(name = "decrypt")
public class DecryptMojo extends BaseMojo {

    @Override
    public void execute() {
        initEngine();
        FieldProcessor fp = buildProcessor();

        if (text == null || text.isEmpty()){
            getLog().info("No -Dtext provided, nothing to decrypt.");
            return;
        }
        String out = fp.decrypt(text);
        getLog().info("Decrypted: " + out);
        System.out.println(out);
    }
}
