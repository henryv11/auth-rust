use crate::{
    domains::session::repository::{create_session, find_active_session, Session},
    error::Error,
    AppData,
};

fn generate_session_token() -> String {
    String::new()
}

pub async fn start_new_session(state: AppData, user_id: i64) -> Result<Session, Error> {
    let token = generate_session_token();
    let session = create_session(&state.database, user_id, token).await?;
    Ok(session)
}

pub async fn get_active_or_start_new_session(
    state: AppData,
    user_id: i64,
) -> Result<Session, Error> {
    let session = match find_active_session(&state.database, user_id).await {
        Ok(session) => Ok(session),
        Err(Error::NotFoundError) => start_new_session(state, user_id).await,
        Err(error) => Err(error),
    }?;
    Ok(session)
}
