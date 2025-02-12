from fastapi import APIRouter,Depends,status
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from models import User,Order
from schemas import OrderModel,OrderStatusModel
from database import session
from fastapi.encoders import jsonable_encoder

order_router=APIRouter(
    prefix="/orders",
    tags=['orders']
)



# JWT Configuration (should match auth_routes.py)
SECRET_KEY = "e0f2ae0014ed721d4b762b869efd34a01ec3bb92bdb361b4aa30d2b2ef96abed"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Get current user function
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = session.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@order_router.get('/')
async def hello():
    return {"message":"Hello World"}

@order_router.post('/order', status_code=status.HTTP_201_CREATED)
async def place_an_order(order: OrderModel, current_user: User = Depends(get_current_user)):
    """
    ## Placing an Order
    This requires:
    - quantity : integer
    - pizza_size: str
    """

    new_order = Order(
        pizza_size=order.pizza_size,
        quantity=order.quantity
    )

    # Use current_user directly
    new_order.user = current_user

    session.add(new_order)
    session.commit()

    response = {
        "pizza_size": new_order.pizza_size,
        "quantity": new_order.quantity,
        "id": new_order.id,
        "order_status": new_order.order_status
    }

    return jsonable_encoder(response)

# Also fix other routes that use current_user
@order_router.get('/orders')
async def list_all_orders(current_user: User = Depends(get_current_user)):
    """
    ## List all orders
    This lists all orders made. It can be accessed by superusers
    """
    # Use current_user directly
    if current_user.is_staff:
        orders = session.query(Order).all()
        return jsonable_encoder(orders)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="You are not a superuser"
    )

@order_router.get('/user/orders')
async def get_user_orders(current_user: User = Depends(get_current_user)):
    """
    ## Get a current user's orders
    This lists the orders made by the currently logged in users
    """
    # Use current_user directly
    return jsonable_encoder(current_user.orders)


@order_router.get('/user/order/{id}/')
async def get_specific_order(id:int,current_user: User = Depends(get_current_user)):
    """
        ## Get a specific order by the currently logged in user
        This returns an order by ID for the currently logged in user
    
    """

    orders=current_user.orders

    for o in orders:
        if o.id == id:
            return jsonable_encoder(o)
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
        detail="No order with such id"
    )


@order_router.put('/order/update/{id}/')
async def update_order(id:int,order:OrderModel,current_user: User = Depends(get_current_user)):
    """
        ## Updating an order
        This udates an order and requires the following fields
        - quantity : integer
        - pizza_size: str
    
    """
    order_to_update=session.query(Order).filter(Order.id==id).first()

    order_to_update.quantity=order.quantity
    order_to_update.pizza_size=order.pizza_size

    session.commit()

    response={
                "id":order_to_update.id,
                "quantity":order_to_update.quantity,
                "pizza_size":order_to_update.pizza_size,
                "order_status":order_to_update.order_status,
            }

    return jsonable_encoder(response)

    
@order_router.patch('/order/update/{id}/')
async def update_order_status(id:int,
        order:OrderStatusModel,
        current_user: User = Depends(get_current_user)):


    """
        ## Update an order's status
        This is for updating an order's status and requires ` order_status ` in str format
    """
    if current_user.is_staff:
        order_to_update=session.query(Order).filter(Order.id==id).first()

        order_to_update.order_status=order.order_status

        session.commit()

        response={
                "id":order_to_update.id,
                "quantity":order_to_update.quantity,
                "pizza_size":order_to_update.pizza_size,
                "order_status":order_to_update.order_status,
            }

        return jsonable_encoder(response)


@order_router.delete('/order/delete/{id}/',status_code=status.HTTP_204_NO_CONTENT)
async def delete_an_order(id:int,current_user: User = Depends(get_current_user)):

    """
        ## Delete an Order
        This deletes an order by its ID
    """

    order_to_delete=session.query(Order).filter(Order.id==id).first()

    session.delete(order_to_delete)

    session.commit()

    return order_to_delete