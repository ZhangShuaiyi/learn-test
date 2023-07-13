use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::{Client, ResourceExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let pods: Api<Pod> = Api::default_namespaced(client);

    let lp = ListParams::default();
    let p_list = pods.list(&lp).await?;
    for p in p_list {
        println!("Found pod: {}", p.name_any());
    }

    let p = pods.get("hello-pod").await?;
    println!("Got hello-pod pod with containers: {:?}", p.spec.unwrap().containers);
    Ok(())
}
