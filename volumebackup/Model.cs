using System;

namespace Oracle.Oci 
{
    public class DefinedTags { }
    public class SystemTags { }
    public class FreeformTags { }
    public class RootObject
    {
        public string availabilityDomain { get; set; }
        public string compartmentId { get; set; }
        public DefinedTags definedTags { get; set; }
        public SystemTags systemTags { get; set; }
        public string displayName { get; set; }
        public FreeformTags freeformTags { get; set; }
        public string id { get; set; }
        public string imageId { get; set; }
        public bool isHydrated { get; set; }
        public int vpusPerGB { get; set; }
        public string lifecycleState { get; set; }
        public int sizeInGBs { get; set; }
        public int sizeInMBs { get; set; }
        public object sourceDetails { get; set; }
        public DateTime timeCreated { get; set; }
        public string volumeGroupId { get; set; }
        public object kmsKeyId { get; set; }
    }

    public class BackupVolume 
    {
        public string bootVolumeId { get; set; }

        public string displayName { get; set; }

        public string id { get; set; }
    }

    public class CopyVolume 
    {
        public CopyVolume(string destinationRegion)
        {
            this.destinationRegion = destinationRegion;
        }
        
        public string destinationRegion { get; set; }
    }
}