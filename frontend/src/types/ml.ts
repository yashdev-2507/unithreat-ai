/**
 * ML Prediction Record
 * Source of truth: contracts/ml-prediction-schema.json
 */

export interface MlPrediction {
  flow_id: string;
  threat_class: string;
  /** Score between 0 and 1 */
  score: number;
  model_version: string;
  calibrated?: boolean;
}
