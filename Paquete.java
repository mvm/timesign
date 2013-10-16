import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author ribadas
 */
public class Paquete {

    private Map<String, Bloque> bloques;

    public Paquete() {
        this.bloques = new HashMap<String, Bloque>();
    }

    public Paquete(Map<String, Bloque> bloques) {
        this.bloques = bloques;
    }

    public Bloque getBloque(String nombreBloque) {
        Bloque result = null;
        if (this.bloques != null) {
            String nombreBloqueNormalizado = normalizarNombre(nombreBloque);
            result = this.bloques.get(nombreBloqueNormalizado);
        }
        return result;
    }

    public void anadirBloque(String nombreBloque, Bloque bloque) {
        if (this.bloques == null) {
            this.bloques = new HashMap<String, Bloque>();
        }
        String nombreBloqueNormalizado = normalizarNombre(nombreBloque);
        this.bloques.put(nombreBloqueNormalizado, bloque);
    }

    public void eliminarBloque(String nombreBloque) {
        if (this.bloques != null) {
            if (this.bloques.containsKey(nombreBloque)) {
                this.bloques.remove(nombreBloque);
            }
        }
    }

    public List<String> getNombresBloque() {
        List<String> result = new ArrayList<String>();
        if (this.bloques != null) {
            for (String nombre : this.bloques.keySet()) {
                result.add(nombre);
            }
        }
        return result;
    }

    private String normalizarNombre(String nombreBloque) {
        String result = nombreBloque.replaceAll(" ", "_").toUpperCase();
        return result;
    }
}
