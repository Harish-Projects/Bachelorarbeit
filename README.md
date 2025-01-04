**"Live Intrusion Detection System mit Shallow Machine Learning: Vergleich und Evaluation von Modellen in IoT- und IIoT-Umgebungen"**

<ins>Dataset:</ins> Edge-IIoT-Set (2022)

<ins>Models:</ins> The Target classes can be classified in 2 or 6 or 15 classes.
* Binary classsifier;
  * SVC - Model with SVM techniques.[Supervised]<br>
  * KNN - Model with cluster techniques.[Supervised]<br>
  * Local Outlier Factor - Model with density based techniques.[semi-supervised]<br>
  * Random Forest - Model with decison tree based techniques.[supervised]<br>
* Multiclass classifier;
  * SVC - SVM technique with non linear kernel trick and ONE-vs-ONE method.[Supervised]<br>
  * Linear SVC - Model with linear kernel and ONE-vs-REST method.[Supervised]<br>
  * KNN - Cluster technique.[Supervised]<br>
  * RF - Decision tree multiclass classifier.[supervised]<br> 

<ins>Evaluation:</ins> Accuracy, Precision, Recall, F1, Confusion Matrix and Novel Percentage. Novel percentage evaluates a Total True Positive when a model is trained with *leaving one target class out* approach. 

<ins>Directory Structure:</ins> 
* Source [contains developed models with Hyperparameters evaluation and Dimendsion Reduction tests]
  * Pipelines [Binary and Multi class classifier models as Pipelines]
  * Dimension_Reduction [Feature selection by RF and Featurte reduction by PCA]
  * Hyperparameter [Hyperparameters for all models are determined here]
* Docker [Docker files for network Simulation]
  * data/* [deployed models as pickle file and pcap file for replaytraffic]
  * compose.yaml [launch two dockerfiles mentione below]
  * Dockerfile [docker file for replaying traffic]
  * Dockerfile.tshark [docker file for live IDS]
  * feature_pipeline.py [script for parsing the packets and models are deloyed to predict network flow]
  * custom_classes.py [custom built class for sampling reduction used only in training the model but it is necessary for pipeline]
  * more on Readme.md
* Misc [Junks created during development]