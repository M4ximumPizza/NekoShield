package mi.m4x.project.nekoshield;

import java.util.List;

/**
 * Class for storing Nekodetector scan results.
 *
 * @author Logan Abernathy (https://github.com/M4ximumPizza)
 */
public class Results {

    /**
     * List of detections for stage 1.
     */
    private List<String> stage1Detections;

    /**
     * List of detections for stage 2.
     */
    private List<String> stage2Detections;

    /**
     * Creates a new instance of Results with the given stage 1 and stage 2 detections.
     *
     * @param stage1Detections List of detections for stage 1.
     * @param stage2Detections List of detections for stage 2.
     */
    public Results(List<String> stage1Detections, List<String> stage2Detections) {
        this.stage1Detections = stage1Detections;
        this.stage2Detections = stage2Detections;
    }

    /**
     * Returns the list of detections for stage 1.
     *
     * @return List of detections for stage 1.
     */
    public List<String> getStage1Detections() {
        return stage1Detections;
    }

    /**
     * Returns the list of detections for stage 2.
     *
     * @return List of detections for stage 2.
     */
    public List<String> getStage2Detections() {
        return stage2Detections;
    }
}
